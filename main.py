"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: nloginov
Script Name: Discord Favorite Gif Downloader (Async Version)
"""

import asyncio
import aiohttp
import base64
import re
import os
from bs4 import BeautifulSoup
import logging
import time
import json
from collections import defaultdict
import hashlib
from urllib.parse import urlparse, urlunparse, unquote, parse_qs
import ssl

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# Global counters and error tracking
total_urls = 0
successful_downloads = 0
failed_downloads = 0
error_summary = defaultdict(list)
detailed_errors = {
    "429": [],
    "404": [],
    "content-type": [],
    "other": []
}

# Async configuration
MAX_CONCURRENT_DOWNLOADS = 5  # Reduced to prevent overwhelming servers
MAX_RETRIES = 2  # Reduced retry attempts
RETRY_DELAY = 5  # Reduced delay
REQUEST_TIMEOUT = 20  # Reduced timeout

# Locks for thread-safe operations
download_lock = asyncio.Lock()

def ensure_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def extract_and_fix_urls(text):
    """Extract and repair malformed URLs from Discord's decrypted base64 favorite GIFs data."""
    pattern = r'(?:https?:?/?/?|ftp:?/?/?|www\.)[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
    urls = re.findall(pattern, text)
    
    fixed_urls = []
    for url in urls:
        try:
            # Fix protocol issues
            if url.startswith('http/'): url = 'http://' + url[5:]
            elif url.startswith('https/'): url = 'https://' + url[6:]
            elif url.startswith('ftp/'): url = 'ftp://' + url[4:]
            elif url.startswith('www.'): url = 'https://' + url
            
            # Fix slash issues
            url = re.sub(r'^(https?|ftp):/{3,}', r'\1://', url)
            url = re.sub(r'^(https?|ftp):(?!/)', r'\1://', url)
            
            # Handle Discord external URLs
            if 'discordapp.net/external/' in url or 'discord.com/external/' in url:
                extracted_urls = extract_discord_external_url(url)
                if extracted_urls:
                    fixed_urls.extend(extracted_urls)
                    continue
            
            # Handle Discord CDN URLs
            if ('cdn.discordapp.com' in url or 'media.discordapp.net' in url) and not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Handle double URL encoding
            prev_url = ""
            while prev_url != url and '%' in url:
                prev_url = url
                url = unquote(url)
            
            # Clean up malformations
            url = re.sub(r'["\'\s]+$', '', url)  # Remove trailing quotes/spaces
            url = url.replace('\\/', '/').replace('\\"', '"')  # Fix escaped chars
            url = re.sub(r'(?<!:)//+', '/', url)  # Remove duplicate slashes
            url = re.sub(r'&amp;', '&', url)  # Fix HTML entities
            
            # Final validation
            parsed = urlparse(url)
            if (parsed.scheme in ('http', 'https', 'ftp') and 
                parsed.netloc and 
                '.' in parsed.netloc and 
                not parsed.netloc.startswith('.') and 
                not parsed.netloc.endswith('.') and
                re.match(r'^[a-zA-Z0-9\-._]+$', parsed.netloc.split(':')[0])):
                fixed_urls.append(parsed.geturl())
        except:
            continue
    
    return list(dict.fromkeys(fixed_urls))  # Remove duplicates

def extract_discord_external_url(url):
    """Improved Discord external URL extraction"""
    try:
        # Parse the URL
        parsed = urlparse(url)
        
        # Method 1: Extract from path
        if '/external/' in parsed.path:
            # Split path and get everything after /external/
            path_parts = parsed.path.split('/external/')
            if len(path_parts) > 1:
                remaining_path = path_parts[1]
                # Remove the hash part (first segment) and get the actual URL
                segments = remaining_path.split('/')
                if len(segments) > 1:
                    # The actual URL starts after the hash
                    actual_url = '/'.join(segments[1:])
                    # URL decode it
                    decoded_url = unquote(actual_url)
                    if decoded_url.startswith(('http://', 'https://')):
                        return [decoded_url]
        
        # Method 2: Look for embedded URLs in the entire string
        # Find all potential URLs in the string
        url_patterns = [
            r'https?://[^\s/?#]+[^\s]*',
            r'(?:https?://)?(?:www\.)?[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+\.(?:gif|jpg|jpeg|png|mp4|webm)'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, url)
            for match in matches:
                if match.startswith(('http://', 'https://')) and match != url:
                    # Decode multiple times if needed
                    decoded_match = match
                    for _ in range(3):  # Max 3 decode attempts
                        try:
                            new_decoded = unquote(decoded_match)
                            if new_decoded == decoded_match:
                                break
                            decoded_match = new_decoded
                        except:
                            break
                    
                    # Validate the extracted URL
                    try:
                        parsed_match = urlparse(decoded_match)
                        if (parsed_match.scheme in ('http', 'https') and 
                            parsed_match.netloc and 
                            '.' in parsed_match.netloc):
                            return [decoded_match]
                    except:
                        continue
        
        # Method 3: Query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for param in ['url', 'uri', 'source', 'image']:
                if param in query_params:
                    value = query_params[param][0]
                    decoded_value = unquote(value)
                    if decoded_value.startswith(('http://', 'https://')):
                        return [decoded_value]

        # Method 4: Fragment
        if parsed.fragment:
            fragment = unquote(parsed.fragment)
            if fragment.startswith(('http://', 'https://')):
                return [fragment]
                
    except Exception as e:
        logger.debug(f"Error parsing Discord external URL {url}: {e}")
    
    return None

async def get_imgur_url(session, imgur_url):
    try:
        # First try to get as text (for HTML pages)
        try:
            async with session.get(imgur_url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    if 'text/html' in content_type:
                        content = await response.text()
                        
                        # Clean URL by removing query parameters and fragments
                        def clean_url(url):
                            if not url:
                                return None
                            parsed = urlparse(url)
                            return urlunparse(parsed._replace(query='', fragment=''))

                        # Try to extract JSON data (for gallery pages)
                        json_match = re.search(r'window\.postDataJSON="({.+?})"', content)
                        if json_match:
                            try:
                                data = json.loads(json_match.group(1).replace('\\"', '"'))
                                if data.get('is_album', False) and 'media' in data:
                                    return [clean_url(item.get('url')) for item in data['media'] if item.get('url')]
                            except (json.JSONDecodeError, AttributeError):
                                pass

                        # For all album types (/a/ and /gallery/), look for meta tags and embedded images
                        image_urls = set()

                        # Check OpenGraph meta tags
                        og_image_match = re.search(r'<meta property="og:image" [^>]*content="([^"]+)"', content)
                        if og_image_match:
                            image_urls.add(clean_url(og_image_match.group(1)))

                        # Check Twitter card meta tags
                        twitter_image_match = re.search(r'<meta name="twitter:image" [^>]*content="([^"]+)"', content)
                        if twitter_image_match:
                            image_urls.add(clean_url(twitter_image_match.group(1)))

                        # Find all direct image links in the page
                        direct_urls = re.findall(r'https://i\.imgur\.com/\w+\.(?:jpg|png|gif|jpeg|mp4)', content)
                        image_urls.update(clean_url(url) for url in direct_urls)

                        # If we found any URLs, return them (remove None values)
                        found_urls = [url for url in image_urls if url]
                        if found_urls:
                            return found_urls
                            
        except UnicodeDecodeError:
            # If we get a decoding error, it's probably binary data - treat as direct image
            pass

        # If nothing found or decoding failed, try to construct URL from ID
        imgur_id = imgur_url.split('/')[-1].split('.')[0]  # Handle cases with extensions
        return [f'https://i.imgur.com/{imgur_id}.jpg']

    except Exception as e:
        logger.debug(f"Error fetching Imgur URL {imgur_url}: {e}")
        return None


async def get_tenor_gif_url(session, tenor_url):
    """Extract direct GIF URL from Tenor page"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }

        try:
            async with session.get(tenor_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    if 'text/html' in content_type:
                        content = await response.text()
                        
                        # Method 1: Extract from meta tag contentUrl
                        content_url_pattern = r'<meta itemprop="contentUrl" content="([^"]+)"'
                        content_url_match = re.search(content_url_pattern, content)
                        if content_url_match:
                            return content_url_match.group(1)
                        
                        # Method 2: Extract from img src in the main gif container
                        img_pattern = r'<img src="(https://media[0-9]*\.tenor\.com/[^"]+\.gif)"[^>]*alt="[^"]*"[^>]*fetchpriority="high"'
                        img_match = re.search(img_pattern, content)
                        if img_match:
                            return img_match.group(1)
                        
                        # Method 3: Extract any media URL from the content
                        media_pattern = r'https://media[0-9]*\.tenor\.com/[^"\'>\s]+\.(?:gif|mp4|webm)'
                        media_matches = re.findall(media_pattern, content)
                        if media_matches:
                            # Prefer GIF over other formats
                            gif_urls = [url for url in media_matches if url.endswith('.gif')]
                            if gif_urls:
                                return gif_urls[0]
                            return media_matches[0]
                        
                        # Method 4: Extract from clipboard data attributes
                        clipboard_pattern = r'data-clipboard-text="(https://media[0-9]*\.tenor\.com/[^"]+\.gif)"'
                        clipboard_match = re.search(clipboard_pattern, content)
                        if clipboard_match:
                            return clipboard_match.group(1)
        except UnicodeDecodeError:
            # If we get a decoding error, it's probably binary data - treat as direct image
            pass

    except Exception as e:
        print(f"Error fetching Tenor URL {tenor_url}: {e}")
    
    return None

CONTENT_TYPES = {
    'image/gif': ('.gif', 'gif'),
    'video/mp4': ('.mp4', 'mp4'),
    'image/png': ('.png', 'img'),
    'image/jpeg': ('.jpg', 'img'),
    'video/webm': ('.webm', 'webm'),
    'image/webp': ('.webp', 'img')
}

SUPPORTED_EXTENSIONS = tuple(ext for ext, _ in CONTENT_TYPES.values())

def get_extension_and_subfolder(content_type, direct_url):
    for mime, (ext, subfolder) in CONTENT_TYPES.items():
        if mime in content_type or direct_url.lower().endswith(ext):
            return ext, subfolder
    return None, None

def safe_filename(filename, max_length=200):
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    
    # Truncate if too long, but keep the extension
    name, ext = os.path.splitext(filename)
    if len(name) > max_length:
        # Use a hash of the full name to ensure uniqueness
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        name = name[:max_length-9] + '_' + name_hash
    
    return name + ext

def should_retry(status_code, error_type, error_message):
    """Determine if we should retry based on the error"""
    if status_code == 429:  # Too Many Requests
        return True
    if status_code in [502, 503, 504]:  # Server errors
        return True
    if "timeout" in str(error_message).lower():
        return True
    if "connection" in str(error_message).lower():
        return True
    return False

async def download_media(session, url, retry_count=0):
    global successful_downloads, failed_downloads
    
    try:
        # First handle special cases (Imgur, Tenor)
        if 'imgur.com' in url:
            imgur_urls = await get_imgur_url(session, url)
            if not imgur_urls:
                async with download_lock:
                    failed_downloads += 1
                    error_summary["Imgur URL skipped"].append(url)
                    detailed_errors["other"].append({
                        "link": url,
                        "reason": "Failed to extract Imgur URL"
                    })
                return
                
            if isinstance(imgur_urls, list) and len(imgur_urls) > 1:  # It's an album
                # Create tasks for all images in the album
                tasks = [download_media(session, imgur_url) for imgur_url in imgur_urls]
                await asyncio.gather(*tasks, return_exceptions=True)
                return
            else:  # Single image/video
                direct_url = imgur_urls[0] if isinstance(imgur_urls, list) else imgur_urls
                
        elif 'tenor.com' in url:
            gif_url = await get_tenor_gif_url(session, url)
            if not gif_url:
                async with download_lock:
                    failed_downloads += 1
                    error_summary["Tenor URL skipped"].append(url)
                    detailed_errors["other"].append({
                        "link": url,
                        "reason": "Failed to extract Tenor URL"
                    })
                return
            direct_url = gif_url
            
        elif url.lower().endswith(SUPPORTED_EXTENSIONS):
            direct_url = url
        else:
            direct_url = url

        # Special handling for Discord external URLs that might still have tracking parameters
        if 'discordapp.net/external/' in direct_url or 'discord.com/external/' in direct_url:
            # Try to extract the final URL again
            extracted_urls = extract_discord_external_url(direct_url)
            if extracted_urls and extracted_urls[0] != direct_url:
                return await download_media(session, extracted_urls[0], retry_count)

        # Create SSL context that's more permissive for retries
        ssl_context = None
        if retry_count > 0:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        async with session.get(
            direct_url,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ssl=ssl_context
        ) as response:
            # Handle redirects
            if response.status in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    if retry_count < MAX_RETRIES:
                        logger.debug(f"Following redirect from {direct_url} to {redirect_url}")
                        return await download_media(session, redirect_url, retry_count + 1)
                    else:
                        raise Exception(f"Too many redirects for {url}")
            
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '').lower()
            
            extension, subfolder = get_extension_and_subfolder(content_type, direct_url)
            if not extension:
                async with download_lock:
                    failed_downloads += 1
                    error_summary["Unsupported content type"].append(f"{content_type} - {direct_url}")
                    detailed_errors["content-type"].append({
                        "link": direct_url,
                        "content-type": content_type
                    })
                return

            parsed_url = urlparse(unquote(direct_url))
            filename = os.path.basename(parsed_url.path)
            filename, _ = os.path.splitext(filename)
            
            if not filename or filename == extension:
                path_parts = parsed_url.path.rstrip('/').split('/')
                filename = path_parts[-1] if path_parts else 'unnamed'
            
            filename = safe_filename(filename + extension)

            download_dir = os.path.join('downloaded', subfolder)
            ensure_directory(download_dir)

            # Handle file naming conflicts
            counter = 1
            original_filename = filename
            while os.path.exists(os.path.join(download_dir, filename)):
                name, ext = os.path.splitext(original_filename)
                filename = f"{name}_{counter}{ext}"
                counter += 1

            full_path = os.path.join(download_dir, filename)
            
            # Read content and write to file
            content = await response.read()
            with open(full_path, 'wb') as file:
                file.write(content)
            
            async with download_lock:
                successful_downloads += 1
                progress = (successful_downloads + failed_downloads) / total_urls * 100
                logger.info(f"Downloaded: {filename} ({progress:.1f}% complete)")
                
    except Exception as e:
        error_type = "other"
        status_code = None
        
        if hasattr(e, 'status'):
            status_code = e.status
            if status_code == 404:
                error_type = "404"
                async with download_lock:
                    error_summary[f"HTTP {status_code}"].append(url)
                    detailed_errors["404"].append({"link": url})
            elif status_code == 429:
                error_type = "429"
                async with download_lock:
                    error_summary[f"HTTP {status_code}"].append(url)
                    detailed_errors["429"].append({"link": url})
            else:
                async with download_lock:
                    error_summary[f"HTTP {status_code}"].append(url)
                    detailed_errors["other"].append({
                        "link": url,
                        "reason": f"HTTP {status_code}"
                    })
        else:
            async with download_lock:
                error_summary["Other errors"].append(f"{url} - {str(e)}")
                detailed_errors["other"].append({
                    "link": url,
                    "reason": str(e)
                })
        
        # Implement improved retry logic
        if retry_count < MAX_RETRIES and should_retry(status_code, error_type, str(e)):
            retry_count += 1
            # Use shorter, non-blocking delay
            wait_time = min(RETRY_DELAY * retry_count, 10)  # Cap at 10 seconds
            logger.debug(f"Retry attempt {retry_count}/{MAX_RETRIES} for {url} after {wait_time} seconds...")
            await asyncio.sleep(wait_time)
            return await download_media(session, url, retry_count)
        
        async with download_lock:
            failed_downloads += 1

def read_input_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    if file_path.lower().endswith('.json'):
        try:
            json_data = json.loads(content)
            if 'settings' in json_data:
                content = json_data['settings']
            else:
                logger.warning("JSON file does not contain 'settings' key. Using raw content.")
        except json.JSONDecodeError:
            logger.warning("Invalid JSON format. Using raw content.")

    try:
        decoded_content = base64.b64decode(content).decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError):
        logger.warning("Content is not valid base64 or couldn't be decoded. Using raw content.")
        decoded_content = content

    return decoded_content

def get_input_file():
    for ext in ['txt', 'json']:
        filename = f'data.{ext}'
        if os.path.exists(filename):
            return filename
    logger.error("No valid input file found. Please ensure 'data.txt' or 'data.json' exists.\nNote: If your filename is 'data.txt', only raw data from 'settings' key must be inside of it.")
    return None

def write_error_log():
    """Write detailed error information to a JSON file"""
    ensure_directory('logs')
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    error_log_path = os.path.join('logs', f'error_log_{timestamp}.json')
    
    # Remove empty categories
    cleaned_errors = {k: v for k, v in detailed_errors.items() if v}
    
    with open(error_log_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_errors, f, indent=4)
    
    logger.info(f"Detailed error log written to {error_log_path}")

async def main():
    global total_urls
    
    input_file = get_input_file()
    if not input_file:
        return

    decoded_content = read_input_file(input_file)
    urls = extract_and_fix_urls(decoded_content)
    total_urls = len(urls)

    logger.info(f"Found {total_urls} URLs to process")
    logger.info(f"Using {MAX_CONCURRENT_DOWNLOADS} concurrent downloads")

    # Create aiohttp session with improved settings
    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT_DOWNLOADS * 2,
        limit_per_host=MAX_CONCURRENT_DOWNLOADS,
        ttl_dns_cache=300,
        use_dns_cache=True,
        ssl=False  # Allow SSL errors to be handled per-request
    )
    
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    ) as session:
        # Create semaphore to limit concurrent downloads
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
        
        async def download_with_semaphore(url):
            async with semaphore:
                try:
                    await download_media(session, url)
                except Exception as e:
                    logger.error(f"Unhandled exception for {url}: {e}")
                    async with download_lock:
                        detailed_errors["other"].append({
                            "link": url,
                            "reason": f"Unhandled: {str(e)}"
                        })

        # Create tasks for all URLs
        tasks = [download_with_semaphore(url) for url in urls]
        
        # Execute all downloads concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

    # Write detailed error log to file
    if any(detailed_errors.values()):
        write_error_log()

    # Print statistics
    logger.info("\n--- Download Statistics ---")
    logger.info(f"Total URLs processed: {total_urls}")
    logger.info(f"Successful downloads: {successful_downloads}")
    logger.info(f"Failed downloads: {failed_downloads}")
    if total_urls > 0:
        logger.info(f"Success rate: {successful_downloads/total_urls*100:.1f}%")

    # Print error summary
    if error_summary:
        logger.info("\n--- Error Summary ---")
        for error_type, urls in error_summary.items():
            logger.info(f"{error_type}: {len(urls)} occurrences")
            if error_type == "HTTP 404":
                logger.info("Sample URLs (max 5):")
                for url in urls[:5]:
                    logger.info(f"  - {url}")
            elif len(urls) <= 5:
                for url in urls:
                    logger.info(f"  - {url}")
            else:
                logger.info(f"  (Showing first 5 of {len(urls)} errors)")
                for url in urls[:5]:
                    logger.info(f"  - {url}")
                logger.info(f"  See error log file for complete list")

    # Pause for 10 seconds
    logger.info("\nScript finished. Exiting in 10 seconds...")
    await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(main())