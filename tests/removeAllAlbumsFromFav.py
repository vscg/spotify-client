from spotify_client import SpotifyClient
import json
import numpy as np

SPOTIFY_CLIENT_ID = ''
SPOTIFY_SECRET_KEY = ''
TOKEN = ''

client = SpotifyClient(SPOTIFY_CLIENT_ID, SPOTIFY_SECRET_KEY, identifier='test-spotify-client')

albums=[]
Offset=0
Limit=50
cont=True
while cont:
    response  = client.getAllAlbum(limit=Limit, offset=Offset, auth_code=TOKEN)
    total = response['total']
    cont=Offset<total
    Offset=Offset+Limit
    for album in response['items']:
        albums.append(album['album']['id'])

for album in albums:
    client.removeAlbum(album, TOKEN)
