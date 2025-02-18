from flask import Flask,render_template,request,redirect,url_for,flash,session,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from spotipy.oauth2 import SpotifyOAuth
import os
import requests
import spotipy

load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'ztr'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spotify_clone.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'


sp_outh = SpotifyOAuth(
    client_id=os.getenv('SPOTIPY_CLIENT_ID'),
    client_secret=os.getenv('SPOTIPY_CLIENT_SECRET'),
    redirect_uri=os.getenv('SPOTIPY_REDIRECT_URI'),
    scope="playlist-read-private user-library-read"
)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True,nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable= False)


def get_access_token():
    url = "https://accounts.spotify.com/api/token"
    data = {
        "grant_type" : 'client_credentials',
        "client_id" : CLIENT_ID,
        "client_secret" : CLIENT_SECRET,
    }
    response = requests.post(url, data=data)
    response_data = response.json().get('access_token')
    return response_data




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, email= email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.','success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods= ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password= request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password,password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/callback')
def callback():
    session.clear()
    code = request.args.get('code')
    token_info = sp_outh.get_access_token(code)
    session['token_info'] = token_info
    return redirect(url_for('playlists'))

@app.route('/playlists')
def get_playlists():
    token_info = session.get['token_info']
    if not token_info:
        return redirect(url_for('login'))

    sp = spotipy.Spotify(auth=token_info['access_token'])
    playlists = sp.current_user_playlists()

    playlist_data = [
        {"name": p['name'], "image" : p['images'][0]['url'] if p["images"] else ""} 
        for p in playlists['items']
    ]

    return jsonify(playlist_data)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)