# Discord Favorite (.gif) Downloader
This script allows you to download all of your favorite gifs from discord very fast without any bullshit.

![image](https://github.com/womblee/discord-favorite-gif-downloader/assets/52250786/a116dbf0-1171-4cf4-ac6b-4428cf6824ff)

## Additional platforms supported
![tenor-logo-4EA1E41CC2-seeklogo com](https://github.com/womblee/discord-favorite-gif-downloader/assets/52250786/321d4bcc-6919-4e83-aeee-067baaae1f5c)

![5842a969a6515b1e0ad75b05-1022447648 (3)](https://github.com/womblee/discord-favorite-gif-downloader/assets/52250786/9be7ea57-a249-475d-8803-29a0d3227940)

# How to use

## Requirements
**Before running**, make sure you have **Python** and every needed library installed.

_To install needed libraries for this script_:

`pip install -r requirements.txt`

## Usage

1. **cd** into the directory with the script (e.g `cd C:\Users\CuteCat\\Desktop\GifDownloader`)
2. Copy your favorite .gif(s) data and save it to `data.json` (see article below)
3. Run this command: `python main.py`
4. Your .gif(s) should start downloading
   
# How to get data
1. Open the developer tab of your browser via **F12**.
2. Open the **'Network'** tab.
3. Refresh the discord page via **CTRL+R**.
4. Open the gif selector and go into the favorite gifs tab.
5. Now go to the **"{;} 2"** key and select it. _(if you don't see it repeat the process)_
6. Copy the contents of it. _(example provided below)_
```json
{
    "settings": "A LARGE CHUNK OF DATA SHOULD BE HERE"
}
```
![image](https://github.com/womblee/discord-favorite-gif-downloader/assets/52250786/ae7a0858-e17b-44bc-a130-d75ae1d3fcb3)

7. Now I want you to copy the contents of it and save to a file named _'data.json'_
   
   (The data file must be in the **same directory as the script**)
