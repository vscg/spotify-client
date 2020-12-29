from spotify_client import SpotifyClient
import json

SPOTIFY_CLIENT_ID = ''
SPOTIFY_SECRET_KEY = ''

client = SpotifyClient(SPOTIFY_CLIENT_ID, SPOTIFY_SECRET_KEY, identifier='test-spotify-client')

fileObj = open(r"out.txt","a")

albumNamesToSearch = ['Anandam', 'Cheli']

for q in queries:
    response  = client.search(query=q, search_types=['album'])
    ablumsFound = response['albums']['items']
    
    fileObj.write(q)
    fileObj.write('\n')
    fileObj.write('\n')
    
    for album in ablumsFound:
        albumName = album['name']
        albumID = album['id']
        albumURL = album['href']
        date = album['release_date']
        artist = album['artists'][0]['name']
        
        fileObj.write(f'Album : {albumName}')
        fileObj.write('\n')
        fileObj.write(f'Artist : {artist}')
        fileObj.write('\n')
        fileObj.write(f'Date : {date}')
        fileObj.write('\n')
        fileObj.write(f'ID : {albumID}')
        fileObj.write('\n')
        fileObj.write(f'URL : {albumURL}')
        fileObj.write('\n')
        fileObj.write('\n')
    
    fileObj.write('---------------------------------------------------------------')
    fileObj.write('\n')
fileObj.close()