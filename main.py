# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: nloginov
# Script Name: Discord Favorite Gif Downloader

import base64
import re
import requests
from urllib.parse import urlparse, unquote
import os
from bs4 import BeautifulSoup
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# Global counters
total_urls = 0
successful_downloads = 0
failed_downloads = 0

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

def download_media(url):
    global successful_downloads, failed_downloads
    try:
        if url.lower().endswith(('.gif', '.mp4', '.png')):
            direct_url = url
        elif 'tenor.com' in url:
            gif_url = get_tenor_gif_url(url)
            if gif_url:
                direct_url = gif_url
            else:
                logger.debug(f"Skipped Tenor URL: {url}")
                failed_downloads += 1
                return
        else:
            direct_url = url

        response = requests.get(direct_url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'image/gif' in content_type or direct_url.lower().endswith('.gif'):
            extension = '.gif'
            subfolder = 'gif'
        elif 'video/mp4' in content_type or direct_url.lower().endswith('.mp4'):
            extension = '.mp4'
            subfolder = 'mp4'
        elif 'image/png' in content_type or direct_url.lower().endswith('.png'):
            extension = '.png'
            subfolder = 'gif'
        else:
            logger.debug(f"Skipped unsupported content type: {content_type} for URL: {direct_url}")
            failed_downloads += 1
            return

        parsed_url = urlparse(unquote(direct_url))
        filename = os.path.basename(parsed_url.path)
        filename, _ = os.path.splitext(filename)
        
        if not filename or filename == extension:
            path_parts = parsed_url.path.rstrip('/').split('/')
            filename = path_parts[-1] if path_parts else 'unnamed'
        
        filename = re.sub(r'[^\w\-_\. ]', '_', filename)
        filename = filename.strip() or 'unnamed'
        filename += extension

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
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
            logger.debug(f"404 Not Found: {url}")
        else:
            logger.warning(f"Failed to download: {url}")
        failed_downloads += 1

def main():
    global total_urls
    with open('encoded_file.txt', 'r', encoding='utf-8') as file:
        content = file.read()

    try:
        decoded_content = base64.b64decode(content).decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError):
        logger.warning("Content is not valid base64 or couldn't be decoded. Using raw content.")
        decoded_content = content

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

    # Pause for 10 seconds
    logger.info("\nScript finished. Closing in 10 seconds...")
    time.sleep(10)

if __name__ == "__main__":
    main()