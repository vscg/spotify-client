from spotify_client import SpotifyClient
import json
import numpy as np

SPOTIFY_CLIENT_ID = ''
SPOTIFY_SECRET_KEY = ''
TOKEN = ''

client = SpotifyClient(SPOTIFY_CLIENT_ID, SPOTIFY_SECRET_KEY, identifier='test-spotify-client')

albumTraks=[]
Offset=0
Limit=50
cont=True
while cont:
    response  = client.getAllAlbum(limit=Limit, offset=Offset, auth_code=TOKEN)
    total = response['total']
    cont=Offset<total
    Offset=Offset+Limit
    for album in response['items']:
        for track in album['album']['tracks']['items']:
            albumTraks.append(track['id'])

playlisyTraks=[]
playlistID=''
Offset=0
Limit=100
cont=True
while cont:
    response  = client.getPlaylist(limit=Limit, offset=Offset, fields='items(track(name,id))', playlist_id=playlistID)
    cont=len(response['items']) > 0
    Offset=Offset+Limit
    for track in response['items']:
        playlisyTraks.append(track['track']['id'])

traksToAdd = np.setdiff1d(albumTraks,playlisyTraks)
print(len(traksToAdd))

for track in traksToAdd:
    client.addToPlaylist(playlist_id=playlistID, uris='spotify:track:'+track, auth_code=TOKEN)
