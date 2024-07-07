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
Script Name: Discord Favorite Gif Downloader
"""

import base64
import re
import requests
from urllib.parse import urlparse, unquote
import os
from bs4 import BeautifulSoup
import logging
import time
import json
from collections import defaultdict
import hashlib

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# Global counters and error tracking
total_urls = 0
successful_downloads = 0
failed_downloads = 0
error_summary = defaultdict(list)

def ensure_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def extract_and_fix_urls(text):
    pattern = r'https?:?/+[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
    urls = re.findall(pattern, text)
    
    fixed_urls = []
    for url in urls:
        if url.startswith('http/'):
            url = 'http://' + url[5:]
        elif url.startswith('https/'):
            url = 'https://' + url[6:]
        
        url = re.sub(r'^(https?:)/+', r'\1//', url)
        
        if 'discordapp.net/external/' in url:
            parsed = urlparse(url)
            query = parsed.path.split('/')[-1]
            if query.startswith('http'):
                url = unquote(query)
        
        fixed_urls.append(url)
    
    return fixed_urls

def get_imgur_url(imgur_url):
    try:
        # Format for Imgur images
        fmt_url = r'https://i\.imgur\.com/\w+\.(?:jpg|png|gif|mp4)'
        
        # Handle album URLs
        if '/a/' in imgur_url:
            response = requests.get(imgur_url, timeout=10)
            response.raise_for_status()
            # Extract all image URLs from the album page
            image_urls = re.findall(fmt_url, response.text)
            return image_urls if image_urls else None

        # Handle single image/video URLs
        response = requests.get(imgur_url, timeout=10)
        response.raise_for_status()
        content = response.text

        # Try to find direct image/video URL in the page source
        match = re.search(fmt_url, content)
        if match:
            return match.group(0)

        # If direct URL not found, construct it from the imgur ID
        imgur_id = imgur_url.split('/')[-1]
        return f'https://i.imgur.com/{imgur_id}.jpg'

    except requests.exceptions.RequestException:
        pass  # Silently handle the error
    return None

def get_tenor_gif_url(tenor_url):
    try:
        response = requests.get(tenor_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        gif_element = soup.select_one('div.Gif img')
        if gif_element and 'src' in gif_element.attrs:
            return gif_element['src']
        
        meta_content_url = soup.select_one('meta[itemprop="contentUrl"]')
        if meta_content_url and 'content' in meta_content_url.attrs:
            return meta_content_url['content']
        
    except requests.exceptions.RequestException:
        pass  # Silently handle the error
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

def download_media(url):
    global successful_downloads, failed_downloads
    try:
        if 'imgur.com' in url:
            imgur_urls = get_imgur_url(url)
            if imgur_urls:
                if isinstance(imgur_urls, list):  # It's an album
                    for imgur_url in imgur_urls:
                        download_media(imgur_url)  # Recursive call for each image in the album
                    return
                else:  # Single image/video
                    direct_url = imgur_urls
            else:
                failed_downloads += 1
                error_summary["Imgur URL skipped"].append(url)
                return
        elif 'tenor.com' in url:
            gif_url = get_tenor_gif_url(url)
            if gif_url:
                direct_url = gif_url
            else:
                failed_downloads += 1
                error_summary["Tenor URL skipped"].append(url)
                return
        elif url.lower().endswith(SUPPORTED_EXTENSIONS):
            direct_url = url
        else:
            direct_url = url

        response = requests.get(direct_url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        extension, subfolder = get_extension_and_subfolder(content_type, direct_url)
        if not extension:
           failed_downloads += 1
           error_summary["Unsupported content type"].append(f"{content_type} - {direct_url}")
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

        counter = 1
        original_filename = filename
        while os.path.exists(os.path.join(download_dir, filename)):
            name, ext = os.path.splitext(original_filename)
            filename = f"{name}_{counter}{ext}"
            counter += 1

        full_path = os.path.join(download_dir, filename)
        with open(full_path, 'wb') as file:
            file.write(response.content)
        successful_downloads += 1
        progress = (successful_downloads + failed_downloads) / total_urls * 100
        logger.info(f"Downloaded: {filename} ({progress:.1f}% complete)")
    except requests.exceptions.RequestException as e:
        failed_downloads += 1
        if isinstance(e, requests.exceptions.HTTPError):
            error_summary[f"HTTP {e.response.status_code}"].append(url)
        else:
            error_summary["Other errors"].append(f"{url} - {str(e)}")


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

def main():
    global total_urls
    
    input_file = get_input_file()
    if not input_file:
        return

    decoded_content = read_input_file(input_file)

    urls = extract_and_fix_urls(decoded_content)
    total_urls = len(urls)

    for url in urls:
        download_media(url)

    # Print statistics
    logger.info("\n--- Download Statistics ---")
    logger.info(f"Total URLs processed: {total_urls}")
    logger.info(f"Successful downloads: {successful_downloads}")
    logger.info(f"Failed downloads: {failed_downloads}")
    logger.info(f"Success rate: {successful_downloads/total_urls*100:.1f}%")

    # Print error summary
    if error_summary:
        logger.info("\n--- Error Summary ---")
        for error_type, urls in error_summary.items():
            logger.info(f"{error_type}: {len(urls)} occurences")
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

    # Pause for 10 seconds
    logger.info("\nScript finished. Exiting in 10 seconds...")
    time.sleep(10)

if __name__ == "__main__":
    main()
