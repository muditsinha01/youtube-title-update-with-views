import flask as flask
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import _json
import time
import smtplib
import get_data
import os

Num = 0
all_credentials = []
Scopes = ['https://www.googleapis.com/auth/youtube.force-ssl']
Video_Id = os.getenv("Video_Id")
Frequency = int(os.getenv("Frequency"))
API_Service_Name = "youtube"
API_v = "v3"
# an example of client_secret keys from the google api console
CLIENT_SECRETS_FILE = ["client_secret_techraj1.json", "client_secret_techraj2.json", "client_secret_techraj3.json",
                       "client_secret_techraj4.json", "client_secret_techraj5.json", "client_secret_techraj6.json",
                       "client_secret_techraj7.json", "client_secret_techraj8.json"]
app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# Again a sample, replace with actual values from google api console
app.secret_key = os.getenv('SECRET_KEY')


def authorize():
    global Num
    global all_credentials
    Num = flask.session['Num']

    if Num == 8:
        return "All 8 apps are authorized."

    print("Authorizing app %d" % (Num + 1))

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE[NUM],
        ['https://www.googleapis.com/auth/youtube.force-ssl'])
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Generate URL for request to Google's OAuth 2.0 server.
    # Use kwargs to set optional request parameters.
    flask.session['state'] = "state%d" % Num
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        state='state%d' % Num,
        include_granted_scopes='true')

    return flask.redirect(authorization_url)  # redirect to Google's Oauth server for consent


def oauth2callback():
    global Num
    global all_credentials
    # After the consent, we are redirected to this page. We can retrieve the authorization code from here
    Num = flask.session['Num']

    # verify authorization code with state
    state = flask.session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE[Num],
        scopes=['https://www.googleapis.com/auth/youtube.force-ssl'],
        state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # use the flow.fetch_token method to exchange the authorization code in that response for an access token
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Now store credentials in the session
    credentials = flow.credentials
    if not 'credentials' in flask.session:
        flask.session['credentials'] = []
    # 'credentials' : [credentials of first app, credentials of second app]

    all_credentials.append({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes})

    # print("credentials : ",all_credentials)

    Num += 1
    if Num == 8:
        f = open('credentials.txt', 'w')
        f.write(str(all_credentials))
        f.close()
    # Now it can make requests with these credentials
    return "Successfully authorized App %d <a href='/authorize'>Authorize</a> " % Num


def make_title(views):
    title_template = "This video has %s views" % views
    return title_template


def main(flask_credentials):
    ctr = 0
    while True:
        time.sleep(Frequency)
        info = get_data.getinfo()
        updated_title = make_title(info['views'])
        if info['title'].strip() != updated_title.strip():
            pass
        else:
            print("Using app: %d" % (++ctr))
        credentials = google.oauth2.credentials.Credentials(**flask_credentials[ctr])
        youtube = googleapiclient.discovery.build(API_Service_Name, API_v, credentials=credentials)
        try:
            request = youtube.videos.update(part="snippet",
                                            body={'id': Video_Id,
                                                  'snippet': {"Category_Id": 22,
                                                              "default language": "en",
                                                              "title": updated_title,
                                                              "description": info['description']}})
            response = request.execute()
        except:
            print("failure to update correctly")
            ctr = ++ctr
            if ctr != 8:
                continue
            ctr = 0
