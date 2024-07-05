# Discord Favorite (.gif) Downloader
This script allows you to download all of your favorite gifs very fast

![image](https://github.com/womblee/discord-favorite-gif-downloader/assets/52250786/a116dbf0-1171-4cf4-ac6b-4428cf6824ff)

# How to setup
1. Open the developer tab of your browser via **F12**.
2. Open the 'Network' tab.
3. Refresh the discord page via **CTRL + R**.
4. Open the gif selector and go into the favorite gifs tab.
5. Now go to the "{;} 2" key and select it, if you don't see it repeat the process.
6. Copy the contents of it. It should be like this:
```json
{
    "settings": "ENCODED TEXT HERE"
}
```
7. Now I want you to copy the "ENCODED TEXT HERE" portion ONLY and save it to a text file!
8. The file should be named _'encoded_file.txt'_ and must be next to main.py in order for the script to work.

# How to use
cd into the directory with the script, and run: `python main.py`

Before running, make sure you install every needed library:
`pip install -r requirements.txt`
