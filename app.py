"""
app.py - Application principale pour le système de tontine et collecte de fonds
"""
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import uuid
import logging
import markdown
import bleach
import eventlet
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError
from markupsafe import Markup
from slugify import slugify
import time

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

# Configuration de l'application
app = Flask(__name__)
app.config['SECRET_KEY'] = '6d9348c846d2c517894e87b972b517c9'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///tontine.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# ✅ Initialisation unique des extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins=[])

# 🔐 Configuration login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Créer les dossiers nécessaires s'ils n'existent pas
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures'), exist_ok=True)

# Modèles de données (à suivre...)

class UserTontine(db.Model):
    __tablename__ = 'user_tontine'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tontine_id = db.Column(db.Integer, db.ForeignKey('tontine.id'))
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship('User', back_populates='tontines')
    tontine = db.relationship('Tontine', back_populates='members')
    contributions = db.relationship('Contribution', back_populates='user_tontine')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)  # Ajoutez cette ligne

    @staticmethod
    def is_member(user_id, tontine_id):
        return db.session.query(
            UserTontine.query.filter_by(
                user_id=user_id,
                tontine_id=tontine_id
            ).exists()
        ).scalar()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    verified = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relations
    wallet = db.relationship('Wallet', backref='user', uselist=False)
    tontines = db.relationship('UserTontine', back_populates='user')
    contributions = db.relationship('Contribution', back_populates='user')

    @property
    def profile_picture_url(self):
        profile = UserProfilePicture.query.filter_by(user_id=self.id, is_active=True).first()
        if profile and profile.filename:
            url = url_for('static', filename=f'uploads/profile_pictures/{profile.filename}')
            current_app.logger.debug(f"Profile picture URL for user {self.id}: {url}")
            return url
        else:
            url = url_for('static', filename='images/default-avatar.png')
            current_app.logger.debug(f"Default avatar URL for user {self.id}: {url}")
            return url

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False
    @property
    def unread_notifications(self):
        return Notification.query.filter_by(user_id=self.id, read=False).count()

    @property
    def recent_notifications(self, limit=5):
        return Notification.query.filter_by(user_id=self.id).order_by(Notification.created_at.desc()).limit(limit).all()


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tontine_id = db.Column(db.Integer, db.ForeignKey('tontine.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user = db.relationship('User', backref='chat_messages')
    tontine = db.relationship('Tontine', backref='chat_messages')

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    balance = db.Column(db.Float, default=0.0)
    last_transaction = db.Column(db.DateTime)
    transactions = db.relationship('Transaction', backref='wallet', lazy='dynamic')


class Transaction(db.Model):
    __tablename__ = 'transaction'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'))
    amount = db.Column(db.Float)
    transaction_type = db.Column(db.String(20))  # deposit, withdrawal, payment, etc.
    reference = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))

    tontine_cycle_id = db.Column(db.Integer, db.ForeignKey('tontine_cycle.id'), nullable=True)
    tontine_cycle = db.relationship('TontineCycle', backref='transactions')


# Modèles pour le forum
class ForumCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    slug = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)
    
    topics = db.relationship('ForumTopic', backref='category', lazy='dynamic')

class ForumTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('forum_category.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    is_pinned = db.Column(db.Boolean, default=False)
    is_closed = db.Column(db.Boolean, default=False)
    slug = db.Column(db.String(200), unique=True)
    
    user = db.relationship('User')
    posts = db.relationship('ForumPost', backref='topic', lazy='dynamic')

class ForumPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topic.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_first_post = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User')
    likes = db.relationship('ForumLike', backref='post', lazy='dynamic')

class ForumLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')

class UserFollow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    follower = db.relationship('User', foreign_keys=[follower_id])
    followed = db.relationship('User', foreign_keys=[followed_id])
    
class Tontine(db.Model):
    __tablename__ = 'tontine'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    amount_per_member = db.Column(db.Float, nullable=False)
    frequency = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    max_members = db.Column(db.Integer, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=False)  # Nouveau: tontine privée ou publique

    # Relations
    creator = db.relationship('User', backref='tontines_created')
    members = db.relationship('UserTontine', back_populates='tontine', cascade='all, delete-orphan')
    cycles = db.relationship('TontineCycle', back_populates='tontine', cascade='all, delete-orphan')
    join_requests = db.relationship('JoinRequest', back_populates='tontine', lazy='dynamic')

    @property
    def current_members(self):
        """Nombre de membres actifs"""
        return len([m for m in self.members if m.is_active])

    @property
    def contributions(self):
        """Toutes les contributions de la tontine"""
        return [contribution for cycle in self.cycles for contribution in cycle.contributions]

    @property
    def total_contributions(self):
        """Montant total des contributions"""
        return sum(c.amount for c in self.contributions if c.status == 'paid')

    @property
    def next_cycle_date(self):
        """Date du prochain cycle"""
        current_cycle = TontineCycle.query.filter_by(
            tontine_id=self.id,
            is_completed=False
        ).order_by(TontineCycle.start_date.asc()).first()
        
        if current_cycle:
            return current_cycle.end_date
        
        last_cycle = TontineCycle.query.filter_by(
            tontine_id=self.id
        ).order_by(TontineCycle.end_date.desc()).first()
        
        if last_cycle:
            if self.frequency == 'daily':
                return last_cycle.end_date + timedelta(days=1)
            elif self.frequency == 'weekly':
                return last_cycle.end_date + timedelta(weeks=1)
            elif self.frequency == 'monthly':
                return last_cycle.end_date + timedelta(days=30)
        
        return self.start_date

    @property
    def current_cycle(self):
        """Cycle actuel de la tontine"""
        return TontineCycle.query.filter_by(
            tontine_id=self.id,
            is_completed=False
        ).order_by(TontineCycle.start_date.desc()).first()

    @property
    def is_full(self):
        """Vérifie si la tontine est complète"""
        return self.current_members >= self.max_members

    def get_member_status(self, user_id):
        """Statut d'un membre dans la tontine"""
        membership = UserTontine.query.filter_by(
            user_id=user_id,
            tontine_id=self.id
        ).first()
        
        if membership:
            return {
                'is_member': True,
                'is_active': membership.is_active,
                'has_pending_request': False
            }
        
        has_pending = JoinRequest.query.filter_by(
            user_id=user_id,
            tontine_id=self.id,
            status='pending'
        ).first() is not None
        
        return {
            'is_member': False,
            'is_active': False,
            'has_pending_request': has_pending
        }

    def __repr__(self):
        return f'<Tontine {self.name} (ID: {self.id})>'
    
class TontineCycle(db.Model):
    __tablename__ = 'tontine_cycle'

    id = db.Column(db.Integer, primary_key=True)
    tontine_id = db.Column(db.Integer, db.ForeignKey('tontine.id'))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    is_completed = db.Column(db.Boolean, default=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relations
    tontine = db.relationship('Tontine', back_populates='cycles')
    contributions = db.relationship('Contribution', back_populates='cycle')


class Contribution(db.Model):
    __tablename__ = 'contribution'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    cycle_id = db.Column(db.Integer, db.ForeignKey('tontine_cycle.id'))
    user_tontine_id = db.Column(db.Integer, db.ForeignKey('user_tontine.id'))
    amount = db.Column(db.Float)
    payment_method = db.Column(db.String(50))
    transaction_reference = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, paid, late, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    
    # Relations
    user = db.relationship('User', back_populates='contributions')
    cycle = db.relationship('TontineCycle', back_populates='contributions')
    user_tontine = db.relationship('UserTontine', back_populates='contributions')

class FundraisingCampaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    target_amount = db.Column(db.Float)
    current_amount = db.Column(db.Float, default=0.0)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    image_url = db.Column(db.String(200))
    
    # Relations
    donations = db.relationship('Donation', back_populates='campaign')

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('fundraising_campaign.id'))
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    message = db.Column(db.Text)
    is_anonymous = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(50))
    transaction_reference = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    
    # Relations
    campaign = db.relationship('FundraisingCampaign', back_populates='donations')
    donor = db.relationship('User')

class JoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tontine_id = db.Column(db.Integer, db.ForeignKey('tontine.id'), nullable=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('fundraising_campaign.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='join_requests')
    tontine = db.relationship('Tontine', back_populates='join_requests')
    campaign = db.relationship('FundraisingCampaign', backref='join_requests')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(200))  # Optionnel pour des liens cliquables

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))


# Ajoutez ces classes après les autres modèles
class UserProfilePicture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProfileHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    changed_field = db.Column(db.String(50))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    changed_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Pour suivre qui a fait le changement
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)


def time_ago(value):
    """Affiche un texte relatif du temps écoulé depuis la date donnée."""
    if not value:
        return ""
    now = datetime.utcnow()
    diff = now - value

    seconds = diff.total_seconds()
    minutes = seconds / 60
    hours = minutes / 60
    days = diff.days

    if seconds < 60:
        return "à l’instant"
    elif minutes < 60:
        return f"il y a {int(minutes)} minute(s)"
    elif hours < 24:
        return f"il y a {int(hours)} heure(s)"
    elif days < 30:
        return f"il y a {int(days)} jour(s)"
    else:
        return value.strftime("%d %b %Y")  # Date formatée pour les plus anciennes

# Enregistrer le filtre dans Jinja
app.jinja_env.filters['time_ago'] = time_ago


def send_notification(user_id, message, link=None):
    """Crée et envoie une notification"""
    try:
        notification = Notification(
            user_id=user_id,
            message=message,
            link=link,
            read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        # Envoi via Socket.IO si configuré
        if socketio:
            socketio.emit('new_notification', {
                'user_id': user_id,
                'message': message,
                'link': link,
                'unread_count': Notification.query.filter_by(user_id=user_id, read=False).count()
            }, namespace='/notifications')
            
    except Exception as e:
        current_app.logger.error(f"Erreur notification: {str(e)}")
        db.session.rollback()

def notify_tontine_members(tontine_id, message, exclude_user_id=None):
    """Envoie une notification à tous les membres d'une tontine"""
    members = UserTontine.query.filter_by(tontine_id=tontine_id).all()
    for member in members:
        if exclude_user_id and member.user_id == exclude_user_id:
            continue
        send_notification(member.user_id, message)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Veuillez vous connecter pour accéder à cette page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Veuillez vous connecter pour accéder à cette page', 'danger')
            return redirect(url_for('login'))
        
        if not current_user.admin:
            flash('Accès réservé aux administrateurs', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Fonctions utilitaires
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def generate_reference():
    return str(uuid.uuid4()).replace('-', '')[:12].upper()

def update_wallet_balance(user_id, amount, transaction_type, description):
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet:
        wallet = Wallet(user_id=user_id)
        db.session.add(wallet)
    
    if transaction_type == 'deposit':
        wallet.balance += amount
    elif transaction_type == 'withdrawal':
        wallet.balance -= amount
    
    wallet.last_transaction = datetime.utcnow()
    
    transaction = Transaction(
        wallet_id=wallet.id,
        amount=amount,
        transaction_type=transaction_type,
        reference=generate_reference(),
        status='completed',
        description=description
    )
    db.session.add(transaction)
    db.session.commit()
    return transaction

@app.template_filter('format_currency')
def format_currency(value):
    try:
        value = float(value)
        # Format style francophone : 1 234 567,89
        return "{:,.2f}".format(value).replace(",", " ").replace(".", ",")
    except (ValueError, TypeError):
        return "0,00"


@app.template_filter('format_datetime')
def format_datetime(value, format='short'):
    if not isinstance(value, datetime):
        return value
    if format == 'short':
        return value.strftime('%d/%m/%Y %H:%M')
    elif format == 'long':
        return value.strftime('%A %d %B %Y à %H:%M')
    return value.isoformat()

@app.template_filter('format_date')
def format_date(value, format='short'):
    if not isinstance(value, datetime):
        return value
    if format == 'short':
        return value.strftime('%d/%m/%Y')
    elif format == 'long':
        return value.strftime('%A %d %B %Y')
    return value.isoformat()

@app.teardown_appcontext
def shutdown_session(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"[load_user] Erreur SQL: {e}")
        return None



@app.errorhandler(500)
def internal_server_error(error):
    db.session.rollback()
    current_app.logger.error(f"[500] Internal Server Error: {error}")
    return render_template('errors/500.html'), 500

        
# Routes d'authentification
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Pour utilisateur connecté
        user = current_user
        
        # Vérifier si l'utilisateur a des tontines ou en a créé
        has_tontines = db.session.query(UserTontine).filter_by(user_id=user.id).first() is not None
        
        if has_tontines:
            # Afficher les tontines et l'historique seulement si l'utilisateur en a
            user_tontines = db.session.query(Tontine).join(
                UserTontine, UserTontine.tontine_id == Tontine.id
            ).filter(
                Tontine.is_active == True,
                UserTontine.user_id == user.id,
                UserTontine.is_active == True
            ).order_by(Tontine.created_at.desc()).limit(4).all()
            
            wallet = Wallet.query.filter_by(user_id=user.id).first()
            transactions = []
            if wallet:
                transactions = Transaction.query.filter_by(wallet_id=wallet.id)\
                    .order_by(Transaction.created_at.desc()).limit(5).all()
            
            return render_template('index_connected.html',
                               user=user,
                               user_tontines=user_tontines,
                               transactions=transactions,
                               has_tontines=has_tontines)
        else:
            # Nouvel utilisateur sans tontines
            return render_template('index_connected.html',
                               user=user,
                               has_tontines=False)
    else:
        # Pour visiteur non connecté
        return render_template('index_public.html')
    
from sqlalchemy.exc import SQLAlchemyError, IntegrityError


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')

        if not username or not email or not password:
            flash('Veuillez remplir tous les champs obligatoires', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà pris", 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé", 'danger')
            return redirect(url_for('register'))

        try:
            hashed_password = generate_password_hash(password)

            new_user = User(
                public_id=str(uuid.uuid4()),
                username=username,
                email=email,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                phone=phone
            )
            db.session.add(new_user)
            db.session.flush()  # Assigne un ID à new_user sans commit

            new_wallet = Wallet(user_id=new_user.id)
            db.session.add(new_wallet)

            token = session.pop('invite_token', None)
            if token:
                invitation = TontineInvitation.query.filter_by(token=token, accepted=False).first()
                if invitation and not TontineMember.query.filter_by(user_id=new_user.id, tontine_id=invitation.tontine_id).first():
                    membership = TontineMember(user_id=new_user.id, tontine_id=invitation.tontine_id)
                    db.session.add(membership)
                    invitation.accepted = True

            db.session.commit()
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))

        except IntegrityError as e:
            db.session.rollback()
            flash("Erreur de base de données : doublon ou contrainte", 'danger')
            current_app.logger.error(f"[register] IntegrityError: {e}")
            return redirect(url_for('register'))

        except SQLAlchemyError as e:
            db.session.rollback()
            flash("Erreur serveur. Merci de réessayer plus tard.", 'danger')
            current_app.logger.error(f"[register] SQLAlchemyError: {e}")
            return redirect(url_for('register'))

    return render_template('auth/register.html')

@app.teardown_appcontext
def shutdown_session(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Identifiants incorrects', 'danger')
            return redirect(url_for('login'))
        
        # Connexion avec Flask-Login
        login_user(user)
        flash('Connexion réussie!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('auth/login.html')

@app.route('/notifications')
@login_required
def notifications():
    # Nombre de notifications par page
    notifications_per_page = 10
    
    # Récupérer le numéro de page depuis les paramètres GET, défaut à 1
    page = request.args.get('page', 1, type=int)
    
    # Si tu récupères toutes les notifications sous forme de liste (exemple)
    all_notifications = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc()).all()

    # Paginer les notifications manuellement
    start = (page - 1) * notifications_per_page
    end = start + notifications_per_page
    notifications_paginated = all_notifications[start:end]

    # Calculer le nombre total de pages
    total_notifications = len(all_notifications)
    total_pages = (total_notifications // notifications_per_page) + (1 if total_notifications % notifications_per_page > 0 else 0)

    return render_template('notifications/list.html', 
                           notifications=notifications_paginated, 
                           page=page, 
                           total_pages=total_pages)
    

@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    notification.read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/tontine/<int:tontine_id>/request/cancel', methods=['POST'])
@login_required
def cancel_join_request(tontine_id):
    request = JoinRequest.query.filter_by(
        user_id=current_user.id,
        tontine_id=tontine_id,
        status='pending'
    ).first_or_404()
    
    db.session.delete(request)
    db.session.commit()
    
    flash("Votre demande a été annulée", "success")
    return redirect(url_for('tontines_list'))


@app.route('/notifications/count')
@login_required
def notifications_count():
    count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({'count': count})

@app.route('/notifications/recent')
@login_required
def recent_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).limit(5).all()
    
    notifications_data = [{
        'id': n.id,
        'message': n.message,
        'created_at': n.created_at.isoformat(),
        'read': n.read
    } for n in notifs]
    
    return jsonify(notifications_data)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user  # <-- Utilise current_user directement
    
    if not user:
        flash("Utilisateur non trouvé", "danger")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        # Gestion de la photo de profil
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                # Désactiver l'ancienne photo active
                UserProfilePicture.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
                
                # Enregistrer le nouveau fichier
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"{user.public_id}_{datetime.now().timestamp()}.{ext}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures', filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file.save(file_path)
                
                new_picture = UserProfilePicture(
                    user_id=user.id,
                    filename=filename,
                    is_active=True
                )
                db.session.add(new_picture)
                
                # Historique
                history_entry = UserProfileHistory(
                    user_id=user.id,
                    changed_field='profile_picture',
                    old_value='',
                    new_value=filename,
                    changed_by=user.id
                )
                db.session.add(history_entry)
                db.session.commit()

                flash("Photo de profil mise à jour avec succès", "success")
                return redirect(url_for('profile'))

        # Mise à jour des informations
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        if not first_name or not last_name or not email:
            flash("Veuillez remplir tous les champs obligatoires", "danger")
            return redirect(url_for('profile'))

        existing_user = User.query.filter(User.email == email, User.id != user.id).first()
        if existing_user:
            flash("Cet email est déjà utilisé par un autre utilisateur", "danger")
            return redirect(url_for('profile'))

        changes = []
        if user.first_name != first_name:
            changes.append(('first_name', user.first_name, first_name))
        if user.last_name != last_name:
            changes.append(('last_name', user.last_name, last_name))
        if user.email != email:
            changes.append(('email', user.email, email))
        if user.phone != phone:
            changes.append(('phone', user.phone, phone))

        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.phone = phone

        # Mot de passe
        new_password = request.form.get('new_password')
        if new_password:
            if len(new_password) < 6:
                flash("Le mot de passe doit contenir au moins 6 caractères", "danger")
                return redirect(url_for('profile'))
            changes.append(('password', '', 'updated'))
            user.password = generate_password_hash(new_password)

        # Historique
        for field, old_val, new_val in changes:
            history_entry = UserProfileHistory(
                user_id=user.id,
                changed_field=field,
                old_value=str(old_val),
                new_value=str(new_val),
                changed_by=user.id
            )
            db.session.add(history_entry)

        db.session.commit()
        flash("Profil mis à jour avec succès", "success")
        return redirect(url_for('profile'))

    # Données pour affichage GET
    profile_picture = UserProfilePicture.query.filter_by(user_id=user.id, is_active=True).first()
    profile_picture_url = (
        url_for('static', filename=f'uploads/profile_pictures/{profile_picture.filename}')
        if profile_picture else url_for('static', filename='images/avatar-default.png')
    )

    history_entries = UserProfileHistory.query.filter_by(user_id=user.id).order_by(
        UserProfileHistory.changed_at.desc()
    ).all()

    return render_template('profile.html',
                           user=user,
                           profile_picture_url=profile_picture_url,
                           history_entries=history_entries)


# Route pour la page de changement de mot de passe
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        user = User.query.get(session['user_id'])
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not check_password_hash(user.password, current_password):
            flash("Mot de passe actuel incorrect", "danger")
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash("Les nouveaux mots de passe ne correspondent pas", "danger")
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash("Le mot de passe doit contenir au moins 6 caractères", "danger")
            return redirect(url_for('change_password'))
        
        # Mise à jour du mot de passe
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash("Mot de passe changé avec succès", "success")
        return redirect(url_for('profile'))
    
    return render_template('auth/change_password.html')


@app.route('/logout')
def logout():
    logout_user()
    session.clear()  # Nettoie toute la session manuellement si besoin
    flash("Vous avez été déconnecté", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user  # Utilisez current_user au lieu de session['user_id']
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    
    # Vérifier si l'utilisateur a des tontines
    has_tontines = db.session.query(UserTontine).filter_by(user_id=user.id).first() is not None
    
    # Tontines de l'utilisateur (seulement si has_tontines est True)
    user_tontines = []
    if has_tontines:
        user_tontines = UserTontine.query.filter_by(user_id=user.id).all()
        tontine_ids = [ut.tontine_id for ut in user_tontines]
        tontines = Tontine.query.filter(Tontine.id.in_(tontine_ids)).all() if tontine_ids else []
    else:
        tontines = []
    
    # Campagnes de l'utilisateur
    campaigns = FundraisingCampaign.query.filter_by(creator_id=user.id).all()
    
    # Transactions récentes
    transactions = []
    if wallet:
        transactions = Transaction.query.filter_by(wallet_id=wallet.id)\
            .order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('dashboard/index.html', 
                         user=user, 
                         wallet=wallet, 
                         tontines=tontines,
                         campaigns=campaigns,
                         transactions=transactions,
                         has_tontines=has_tontines)



@app.route('/wallet')
@login_required
def wallet():
    user = current_user  # Flask-Login te donne directement l'utilisateur connecté

    wallet = Wallet.query.filter_by(user_id=user.id).first()
    if not wallet:
        wallet = Wallet(user_id=user.id, balance=0.0)
        db.session.add(wallet)
        db.session.commit()

    transactions = Transaction.query.filter_by(wallet_id=wallet.id)\
        .order_by(Transaction.created_at.desc()).all()

    return render_template('wallet/index.html', wallet=wallet, transactions=transactions)



@app.route('/wallet/deposit', methods=['GET', 'POST'])
@login_required
def wallet_deposit():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', '0').replace(',', '.'))
        except ValueError:
            flash('Veuillez entrer un montant valide', 'danger')
            return redirect(url_for('wallet_deposit'))

        description = request.form.get('description', 'Dépôt de fonds')

        if amount <= 0:
            flash('Le montant doit être supérieur à zéro', 'danger')
            return redirect(url_for('wallet_deposit'))

        user = User.query.get(current_user.id)
        transaction = update_wallet_balance(user.id, amount, 'deposit', description)

        flash(f'Dépôt de {amount:.2f} effectué avec succès. Référence: {transaction.reference}', 'success')
        return redirect(url_for('wallet'))

    return render_template('wallet/deposit.html')

@app.route('/wallet/withdraw', methods=['GET', 'POST'])
@login_required
def wallet_withdraw():
    user = User.query.get(current_user.id)
    wallet = Wallet.query.filter_by(user_id=user.id).first()

    if not wallet:
        flash('Portefeuille non trouvé', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', '0').replace(',', '.'))
        except ValueError:
            flash('Veuillez entrer un montant valide', 'danger')
            return redirect(url_for('wallet_withdraw'))

        description = request.form.get('description', 'Retrait de fonds')

        if amount <= 0:
            flash('Le montant doit être supérieur à zéro', 'danger')
            return redirect(url_for('wallet_withdraw'))

        if wallet.balance < amount:
            flash('Solde insuffisant', 'danger')
            return redirect(url_for('wallet_withdraw'))

        transaction = update_wallet_balance(user.id, amount, 'withdrawal', description)

        flash(f'Retrait de {amount:.2f} effectué avec succès. Référence: {transaction.reference}', 'success')
        return redirect(url_for('wallet'))

    return render_template('wallet/withdraw.html', wallet=wallet)
@app.route('/tontines', methods=['GET', 'POST'])
@login_required
def tontines_list():
    search_query = request.args.get('q', '').strip()

    # Tontines où l'utilisateur est membre
    user_memberships = UserTontine.query.filter_by(user_id=current_user.id).all()
    user_tontine_ids = [m.tontine_id for m in user_memberships]

    # Demandes en attente
    pending_requests = JoinRequest.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()
    pending_request_ids = [r.tontine_id for r in pending_requests if r.tontine_id]

    # Tontines à afficher (soit celles où on est membre, soit résultats de recherche)
    tontines = []

    if search_query:
        # Recherche par nom (tontines actives seulement)
        tontines = Tontine.query.filter(
            Tontine.is_active == True,
            Tontine.name.ilike(f'%{search_query}%')
        ).all()
    else:
        # Afficher uniquement les tontines où on est membre
        tontines = Tontine.query.filter(
            Tontine.id.in_(user_tontine_ids)
        ).all()

    return render_template(
        'tontines/list.html',
        tontines=tontines,
        user_tontine_ids=user_tontine_ids,
        pending_request_ids=pending_request_ids,
        search_query=search_query
    )

@app.route('/tontine/<int:tontine_id>/requests/<int:request_id>/approve', methods=['POST'])
@login_required
def approve_request(tontine_id, request_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    join_request = JoinRequest.query.get_or_404(request_id)
    
    # Vérification des droits : doit être créateur ou admin
    if not (current_user.id == tontine.creator_id or current_user.admin):  # Modifié ici
        abort(403)
    
    if tontine.current_members >= tontine.max_members:
        flash("La tontine est complète", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    membership = UserTontine(user_id=join_request.user_id, tontine_id=tontine_id)
    db.session.add(membership)
    
    join_request.status = 'approved'
    
    send_notification(
        join_request.user_id,
        f"Vous avez été accepté dans la tontine '{tontine.name}'",
        url_for('tontine_detail', tontine_id=tontine_id)
    )
    
    db.session.commit()
    flash(f"{join_request.user.username} a été ajouté à la tontine", "success")
    return redirect(url_for('tontine_manage', tontine_id=tontine_id))

@app.route('/tontine/<int:tontine_id>/join-request', methods=['POST'])
@login_required
def request_join_tontine(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier si l'utilisateur est déjà membre
    is_member = UserTontine.query.filter_by(
        user_id=current_user.id, 
        tontine_id=tontine.id
    ).first()
    
    if is_member:
        flash("Vous êtes déjà membre de cette tontine", "info")
        return redirect(url_for('tontines_list'))

    # Vérifier s'il y a déjà une demande en attente
    existing_request = JoinRequest.query.filter_by(
        user_id=current_user.id,
        tontine_id=tontine.id,
        status='pending'
    ).first()
    
    if existing_request:
        flash("Vous avez déjà une demande en attente pour cette tontine", "info")
        return redirect(url_for('tontines_list'))
    
    # Vérifier si la tontine a encore de la place
    if len(tontine.members) >= tontine.max_members:
        flash("Cette tontine a atteint son nombre maximum de membres", "danger")
        return redirect(url_for('tontines_list'))
    
    # Créer la demande
    new_request = JoinRequest(
        user_id=current_user.id,
        tontine_id=tontine.id,
        status='pending'
    )
    
    db.session.add(new_request)
    db.session.commit()
    
    flash("Votre demande a été envoyée au créateur de la tontine", "success")
    return redirect(url_for('tontines_list'))

@app.route('/admin/requests')
@login_required
def admin_requests():
    if not current_user.admin:
        abort(403)

    pending_requests = JoinRequest.query.filter_by(status='pending').all()
    return render_template('admin/requests.html', requests=pending_requests)

@app.route('/tontine/request/<int:tontine_id>', methods=['POST'])
@login_required
def tontine_join_request(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier si déjà membre
    if UserTontine.query.filter_by(user_id=current_user.id, tontine_id=tontine.id).first():
        flash("Vous êtes déjà membre de cette tontine", "warning")
        return redirect(url_for('tontines_list', q=tontine.name))
    
    # Vérifier si demande déjà existante
    if JoinRequest.query.filter_by(
        user_id=current_user.id,
        tontine_id=tontine.id,
        status='pending'
    ).first():
        flash("Vous avez déjà une demande en attente", "info")
        return redirect(url_for('tontines_list', q=tontine.name))
    
    # Créer la demande
    request = JoinRequest(
        user_id=current_user.id,
        tontine_id=tontine.id,
        status='pending'
    )
    db.session.add(request)
    db.session.commit()
    
    flash("Votre demande a été envoyée à l'administrateur", "success")
    return redirect(url_for('tontines_list', q=tontine.name))

@app.route('/my-tontines')
@login_required
def my_tontines():
    # Tontines où l'utilisateur est membre
    memberships = UserTontine.query.filter_by(user_id=current_user.id).all()
    tontine_ids = [m.tontine_id for m in memberships]
    tontines = Tontine.query.filter(Tontine.id.in_(tontine_ids)).all()
    
    return render_template(
        'tontines/my_tontines.html',
        tontines=tontines
    )

@app.route('/admin/join_requests')
@login_required
def view_join_requests():
    if not current_user.admin:
        abort(403)

    requests = JoinRequest.query.filter_by(status='pending').all()
    return render_template('admin/join_requests.html', requests=requests)

@app.route('/admin/requests/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_join_request(request_id):
    request = JoinRequest.query.get_or_404(request_id)
    tontine = Tontine.query.get_or_404(request.tontine_id)
    
    if len(tontine.members) >= tontine.max_members:
        flash("La tontine est complète", "danger")
        return redirect(url_for('tontine_manage', tontine_id=request.tontine_id))  # Redirection modifiée
    
    membership = UserTontine(
        user_id=request.user_id,
        tontine_id=request.tontine_id
    )
    db.session.add(membership)
    request.status = 'approved'
    
    # Notification
    send_notification(
        request.user_id,
        f"Votre demande pour la tontine '{tontine.name}' a été approuvée"
    )
    
    # Notification pour le créateur
    if current_user.id != tontine.creator_id:
        send_notification(
            tontine.creator_id,
            f"{request.user.username} a rejoint votre tontine {tontine.name}"
        )
    
    db.session.commit()
    flash(f"{request.user.username} a été ajouté", "success")
    return redirect(url_for('tontine_manage', tontine_id=request.tontine_id))  # Redirection vers la gestion

@app.route('/admin/requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_join_request(request_id):
    request = JoinRequest.query.get_or_404(request_id)
    
    # Vérification des droits
    tontine = Tontine.query.get_or_404(request.tontine_id)
    if not (current_user.id == tontine.creator_id or current_user.admin):
        abort(403)
    
    request.status = 'rejected'
    db.session.commit()
    
    send_notification(
        request.user_id,
        f"Votre demande pour la tontine '{tontine.name}' a été refusée"
    )
    
    flash("Demande rejetée", "success")
    return redirect(url_for('tontine_manage', tontine_id=request.tontine_id))

@socketio.on('connect', namespace='/notifications')
def handle_notification_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')

from flask_login import current_user
from datetime import datetime, timedelta

@app.route('/tontines/<int:tontine_id>')
def tontine_detail(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    user_id = current_user.id if current_user.is_authenticated else None

    # Vérifier si l'utilisateur est membre
    is_member = False
    if user_id:
        is_member = UserTontine.query.filter_by(user_id=user_id, tontine_id=tontine.id).first() is not None

    # Vérifier si l'utilisateur est le créateur ou admin
    is_creator = user_id == tontine.creator_id
    is_admin = current_user.admin if current_user.is_authenticated else False

    # Récupérer les membres avec leurs contributions
    memberships = UserTontine.query.filter_by(tontine_id=tontine.id).all()
    members_count = len(memberships)

    # Calculer les contributions par membre
    contributions = {}
    for member in memberships:
        total = sum(c.amount for c in member.contributions if c.status == 'paid')
        try:
            amount_per_member_float = float(tontine.amount_per_member)
        except (ValueError, TypeError):
            amount_per_member_float = 0.0
        contributions[member.user_id] = {
            'total': total,
            'complete': total >= amount_per_member_float if amount_per_member_float else False,
            'percentage': (total / amount_per_member_float * 100) if amount_per_member_float > 0 else 0
        }

    # Récupérer les cycles
    cycles = TontineCycle.query.filter_by(tontine_id=tontine.id).order_by(TontineCycle.start_date.desc()).all()
    current_cycle = cycles[0] if cycles else None

    # Récupérer le créateur
    creator = User.query.get(tontine.creator_id)

    # Récupérer l'historique des transactions liés au cycle
    transactions = []
    if current_cycle:
        transactions = Transaction.query.filter_by(tontine_cycle_id=current_cycle.id)\
            .order_by(Transaction.created_at.desc()).limit(10).all()

    # Calculer la date du prochain cycle
    next_cycle_start = None
    if tontine.is_active:
        if current_cycle:
            if current_cycle.end_date and current_cycle.end_date > datetime.utcnow():
                next_cycle_start = current_cycle.end_date
            else:
                if tontine.frequency == 'daily':
                    next_cycle_start = datetime.utcnow() + timedelta(days=1)
                elif tontine.frequency == 'weekly':
                    next_cycle_start = datetime.utcnow() + timedelta(weeks=1)
                elif tontine.frequency == 'monthly':
                    next_cycle_start = datetime.utcnow() + timedelta(days=30)
        else:
            next_cycle_start = datetime.utcnow()

    # Bénéficiaires des cycles
    beneficiary_ids = [c.beneficiary_id for c in cycles if c.beneficiary_id]
    beneficiaries = {u.id: u for u in User.query.filter(User.id.in_(beneficiary_ids)).all()}

    # Calcul du total collecté
    total_collected = sum(
        c.amount
        for m in memberships
        for c in m.contributions
        if c.status == 'paid'
    )

    # Conversion sécurisée de amount_per_member en float pour le calcul total_amount
    try:
        amount_per_member_float = float(tontine.amount_per_member)
    except (ValueError, TypeError):
        amount_per_member_float = 0.0

    # Calcul du total à afficher (cotisation x nombre de membres)
    total_amount = amount_per_member_float * members_count

    return render_template(
        'tontines/detail.html',
        tontine=tontine,
        members_count=members_count,
        memberships=memberships,
        contributions=contributions,
        cycles=cycles,
        cycle=current_cycle,
        current_cycle=current_cycle,
        is_member=is_member,
        is_creator=is_creator,
        is_admin=is_admin,
        current_user=current_user,
        creator=creator,
        transactions=transactions,
        next_cycle_start=next_cycle_start,
        datetime=datetime,
        beneficiaries=beneficiaries,
        amount_per_member=amount_per_member_float,
        total_amount=total_amount,
        total_collected=total_collected
    )


@app.route('/tontine/<int:tontine_id>/pay', methods=['POST'])
@login_required
def make_payment(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    user_id = current_user.id  # ✅ remplacement sûr
    
    membership = UserTontine.query.filter_by(user_id=user_id, tontine_id=tontine.id).first()
    if not membership:
        flash("Vous n'êtes pas membre de cette tontine", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    current_cycle = TontineCycle.query.filter_by(
        tontine_id=tontine.id,
        is_completed=False
    ).order_by(TontineCycle.start_date.desc()).first()
    
    if not current_cycle:
        flash("Aucun cycle actif pour cette tontine", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    existing_payment = Contribution.query.filter_by(
        user_id=user_id,
        cycle_id=current_cycle.id
    ).first()
    
    if existing_payment:
        flash("Vous avez déjà payé pour ce cycle", "info")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet or wallet.balance < tontine.amount_per_member:
        flash("Solde insuffisant dans votre portefeuille", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    new_contribution = Contribution(
        user_id=user_id,
        cycle_id=current_cycle.id,
        user_tontine_id=membership.id,
        amount=tontine.amount_per_member,
        payment_method='wallet',
        transaction_reference=generate_reference(),
        status='paid',
        paid_at=datetime.utcnow()
    )
    
    update_wallet_balance(
        user_id,
        tontine.amount_per_member,
        'withdrawal',
        f'Cotisation tontine {tontine.name} - cycle {current_cycle.id}'
    )
    
    db.session.add(new_contribution)
    db.session.commit()

    send_notification(
        user_id,
        f"Paiement de {tontine.amount_per_member} XOF effectué pour la tontine {tontine.name}"
    )
    
    if tontine.creator_id != user_id:
        send_notification(
            tontine.creator_id,
            f"{current_user.username} a effectué son paiement pour la tontine {tontine.name}"
        )
    
    flash("Paiement effectué avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

@app.route('/tontine/<int:cycle_id>/select_beneficiary', methods=['POST'])
@login_required
def select_beneficiary(cycle_id):
    cycle = TontineCycle.query.get_or_404(cycle_id)
    tontine = Tontine.query.get_or_404(cycle.tontine_id)

    if current_user.id != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    selection_method = request.form.get('selection_method', 'manual')
    beneficiary_id = request.form.get('beneficiary_id')

    if selection_method == 'random':
        paid_members = db.session.query(UserTontine.user_id)\
            .join(Contribution, Contribution.user_tontine_id == UserTontine.id)\
            .filter(
                UserTontine.tontine_id == tontine.id,
                Contribution.cycle_id == cycle.id,
                Contribution.status == 'paid'
            ).all()
        
        if not paid_members:
            flash("Aucun membre n'a payé pour ce cycle", "danger")
            return redirect(url_for('tontine_detail', tontine_id=tontine.id))
        
        beneficiary_id = random.choice(paid_members)[0]

    has_paid = Contribution.query.filter_by(
        user_id=beneficiary_id,
        cycle_id=cycle.id,
        status='paid'
    ).first() is not None

    if not has_paid:
        flash("Le bénéficiaire doit avoir payé pour ce cycle", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    cycle.beneficiary_id = beneficiary_id
    cycle.is_completed = True
    
    amount = tontine.amount_per_member * len(tontine.members)
    beneficiary_wallet = Wallet.query.filter_by(user_id=beneficiary_id).first()
    
    if beneficiary_wallet:
        update_wallet_balance(
            beneficiary_id,
            amount,
            'deposit',
            f'Gain tontine {tontine.name} - cycle {cycle.id}'
        )
    
    db.session.commit()
    
    flash(f"Bénéficiaire sélectionné avec succès ({amount} XOF transférés)", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine.id))


from flask_login import login_required, current_user
from flask import request, redirect, url_for, flash, render_template
from datetime import datetime

@app.route('/tontines/create', methods=['GET', 'POST']) 
@login_required
def tontine_create():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        amount_per_member = float(request.form.get('amount'))
        frequency = request.form.get('frequency')
        max_members = int(request.form.get('max_members'))
        
        new_tontine = Tontine(
            name=name,
            description=description,
            amount_per_member=amount_per_member,
            frequency=frequency,
            start_date=datetime.utcnow(),
            max_members=max_members,
            creator_id=current_user.id  # ✅ Correction ici
        )
        
        db.session.add(new_tontine)
        db.session.commit()
        
        user_tontine = UserTontine(
            user_id=current_user.id,  # ✅ Correction ici
            tontine_id=new_tontine.id
        )
        db.session.add(user_tontine)
        db.session.commit()
        
        flash('Tontine créée avec succès!', 'success')
        return redirect(url_for('tontine_detail', tontine_id=new_tontine.id))
    
    return render_template('tontines/create.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/tontine/<int:tontine_id>/add_member', methods=['GET', 'POST'])
@login_required
def add_member(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)

    # Vérifie que l'utilisateur connecté est le créateur ou un admin
    if current_user.id != tontine.creator_id and not getattr(current_user, 'is_admin', False):
        flash("Vous n'avez pas la permission d'ajouter des membres.", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash("Veuillez entrer un nom d'utilisateur", "warning")
            return redirect(url_for('add_member', tontine_id=tontine_id))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Utilisateur introuvable", "danger")
            return redirect(url_for('add_member', tontine_id=tontine_id))

        # Vérifier si déjà membre
        membership = UserTontine.query.filter_by(user_id=user.id, tontine_id=tontine.id).first()
        if membership:
            flash("Cet utilisateur est déjà membre de la tontine", "info")
            return redirect(url_for('tontine_detail', tontine_id=tontine_id))

        # Vérifier si la tontine n'est pas complète
        current_members = UserTontine.query.filter_by(tontine_id=tontine.id).count()
        if current_members >= tontine.max_members:
            flash("La tontine est complète", "danger")
            return redirect(url_for('tontine_detail', tontine_id=tontine_id))

        # Ajouter le membre
        new_membership = UserTontine(user_id=user.id, tontine_id=tontine.id)
        db.session.add(new_membership)
        db.session.commit()

        flash(f"{username} a été ajouté à la tontine.", "success")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    return render_template('tontines/add_member.html', tontine=tontine)

@app.template_filter('markdown')
def markdown_filter(text):
    if not text:
        return ''
    
    # Liste des balises et attributs autorisés
    allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS).union([
        'p', 'pre', 'code', 'blockquote', 'ul', 'ol', 'li', 'strong', 'em', 'a', 'h1', 'h2', 'h3'
    ])

    
    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title'],
        'code': ['class']
    }
    
    # Convertir le markdown en HTML
    html = markdown.markdown(text)
    
    # Nettoyer le HTML
    clean_html = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )
    
    return Markup(clean_html)

@app.cli.command('init-forum')
def init_forum_command():
    """Initialise les catégories du forum"""
    categories = [
        {'name': 'Présentations', 'description': 'Présentez-vous à la communauté', 'slug': 'presentations'},
        {'name': 'Projets d\'investissement', 'description': 'Partagez vos projets et trouvez des investisseurs', 'slug': 'projets-investissement'},
        {'name': 'Opportunités', 'description': 'Opportunités d\'investissement et partenariats', 'slug': 'opportunites'},
        {'name': 'Tontines', 'description': 'Discussions sur les tontines et systèmes de contribution', 'slug': 'tontines'},
        {'name': 'Finance', 'description': 'Discussions générales sur la finance et l\'économie', 'slug': 'finance'},
        {'name': 'Aide et support', 'description': 'Questions et aide sur la plateforme', 'slug': 'aide-support'},
    ]
    
    for cat_data in categories:
        if not ForumCategory.query.filter_by(slug=cat_data['slug']).first():
            category = ForumCategory(
                name=cat_data['name'],
                description=cat_data['description'],
                slug=cat_data['slug']
            )
            db.session.add(category)
    
    db.session.commit()
    print('Catégories du forum initialisées avec succès')

@app.route('/tontine/<int:tontine_id>/join', methods=['GET'])
@login_required
def tontine_join(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)

    # Vérification supplémentaire
    if UserTontine.is_member(current_user.id, tontine_id):
        flash("Vous êtes déjà membre de cette tontine.", 'info')
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    if tontine.is_full:
        flash("La tontine est déjà complète.", 'warning')
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    new_membership = UserTontine(
        user_id=current_user.id,
        tontine_id=tontine_id
    )
    db.session.add(new_membership)
    db.session.commit()

    flash("Vous avez rejoint la tontine avec succès !", 'success')
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))


@app.route('/tontines/<int:tontine_id>/invite', methods=['GET', 'POST'])
@login_required
def tontine_invite(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    if request.method == 'POST':
        email = request.form['email']
        token = str(uuid.uuid4())
        invitation = TontineInvitation(tontine_id=tontine.id, email=email, token=token)
        db.session.add(invitation)
        db.session.commit()
        # TODO : envoyer mail avec lien url_for('tontine_accept_invite', token=token)
        flash(f"Invitation envoyée à {email}")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    return render_template('tontine_invite.html', tontine=tontine)

@app.route('/tontines/invite/<token>', methods=['GET', 'POST'])
def tontine_accept_invite(token):
    invitation = TontineInvitation.query.filter_by(token=token, accepted=False).first_or_404()
    if not current_user.is_authenticated:
        # Sauvegarder le token en session puis rediriger vers inscription
        session['invite_token'] = token
        flash("Veuillez vous inscrire ou vous connecter pour accepter l'invitation.")
        return redirect(url_for('register'))
    
    # Si utilisateur connecté, on ajoute directement
    member_exists = TontineMember.query.filter_by(user_id=current_user.id, tontine_id=invitation.tontine_id).first()
    if not member_exists:
        membership = TontineMember(user_id=current_user.id, tontine_id=invitation.tontine_id)
        db.session.add(membership)
        invitation.accepted = True
        db.session.commit()
        flash("Vous avez rejoint la tontine !")
    else:
        flash("Vous êtes déjà membre de cette tontine.")
    return redirect(url_for('tontine_detail', tontine_id=invitation.tontine_id))


@app.route('/campaigns')
@login_required
def campaigns_list():
    try:
        user_campaigns = FundraisingCampaign.query.filter_by(
            creator_id=current_user.id,
            is_active=True
        ).all()
    except Exception as e:
        flash("Erreur lors du chargement des campagnes.", "danger")
        user_campaigns = []

    return render_template('campaigns/list.html', campaigns=user_campaigns)


@app.route('/campaigns/<int:campaign_id>')
def campaign_detail(campaign_id):
    campaign = FundraisingCampaign.query.get_or_404(campaign_id)

    donations = Donation.query.filter_by(
        campaign_id=campaign.id,
        status='completed'
    ).order_by(Donation.created_at.desc()).all()

    progress = (campaign.current_amount / campaign.target_amount) * 100 if campaign.target_amount > 0 else 0
    creator = db.session.get(User, campaign.creator_id)


    days_remaining = None
    if campaign.end_date:
        try:
            days_remaining = (campaign.end_date - datetime.utcnow()).days
        except Exception:
            days_remaining = None

    return render_template(
        'campaigns/detail.html',
        campaign=campaign,
        donations=donations,
        progress=progress,
        creator=creator,
        days_remaining=days_remaining
    )



@app.route('/invite-friends')
def invite_friends():
    return render_template('invite_friends.html')

@app.route('/support')
def support():
    return render_template('support.html')


@app.route('/tontine/<int:tontine_id>/chat')
@login_required
def tontine_chat(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    # Vérifier que l'utilisateur est membre
    membership = UserTontine.query.filter_by(user_id=session['user_id'], tontine_id=tontine.id).first()
    if not membership:
        flash("Accès refusé au chat", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    return render_template('tontine/chat.html', tontine=tontine)

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    send(f"{session['username']} a rejoint le chat.", to=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    msg = data['message']
    send(f"{session['username']}: {msg}", to=room)

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, read=False).update({'read': True})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id).update({'read': True})
    db.session.commit()
    flash("Toutes les notifications ont été marquées comme lues", "success")
    return redirect(url_for('notifications'))

@app.route('/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    Notification.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash("Toutes les notifications ont été supprimées.", "success")
    return redirect(url_for('notifications'))  # ou 'dashboard' ou autre page

@app.route('/tontine/<int:tontine_id>/manage')
@login_required
def tontine_manage(tontine_id):
    try:
        tontine = Tontine.query.get_or_404(tontine_id)

        # Vérifier que l'utilisateur est le créateur ou un admin
        if current_user.id != tontine.creator_id and not current_user.admin:
            abort(403)

        members = UserTontine.query.filter_by(tontine_id=tontine.id).all()
        join_requests = JoinRequest.query.filter_by(tontine_id=tontine.id, status='pending').all()

        return render_template(
            'tontines/manage.html',
            tontine=tontine,
            members=members,
            join_requests=join_requests
        )

    except Exception as e:
        current_app.logger.error(f"Erreur gestion tontine: {str(e)}")
        flash("Une erreur est survenue lors de la gestion de la tontine", "danger")
        return redirect(url_for('my_tontines'))

@app.route('/campaigns/create', methods=['GET', 'POST'])
@login_required
def campaign_create():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        try:
            target_amount = float(request.form.get('target_amount'))
        except (ValueError, TypeError):
            flash("Le montant cible est invalide.", "danger")
            return redirect(url_for('campaign_create'))

        end_date_str = request.form.get('end_date')
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
        except ValueError:
            flash("Date de fin invalide.", "danger")
            return redirect(url_for('campaign_create'))
        
        # Gestion de l'image
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_url = url_for('static', filename=f'uploads/{unique_filename}')
        
        # Création de la campagne
        new_campaign = FundraisingCampaign(
            title=title,
            description=description,
            target_amount=target_amount,
            creator_id=current_user.id,
            end_date=end_date,
            image_url=image_url
        )
        
        db.session.add(new_campaign)
        db.session.commit()
        
        flash('Campagne créée avec succès!', 'success')
        return redirect(url_for('campaign_detail', campaign_id=new_campaign.id))
    
    return render_template('campaigns/create.html')


@app.route('/campaigns/<int:campaign_id>/donate', methods=['GET', 'POST'])
@login_required
def campaign_donate(campaign_id):
    campaign = FundraisingCampaign.query.get_or_404(campaign_id)
    user = current_user  # Utilisation de Flask-Login
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
        except (ValueError, TypeError):
            flash('Montant invalide', 'danger')
            return redirect(url_for('campaign_donate', campaign_id=campaign.id))

        message = request.form.get('message')
        is_anonymous = request.form.get('is_anonymous') == 'on'
        payment_method = 'wallet'
        
        if amount <= 0:
            flash('Le montant doit être supérieur à zéro', 'danger')
            return redirect(url_for('campaign_donate', campaign_id=campaign.id))
        
        if wallet is None or wallet.balance < amount:
            flash('Solde insuffisant dans votre portefeuille', 'danger')
            return redirect(url_for('campaign_donate', campaign_id=campaign.id))
        
        # Créer la donation
        new_donation = Donation(
            campaign_id=campaign.id,
            donor_id=user.id,
            amount=amount,
            message=message,
            is_anonymous=is_anonymous,
            payment_method=payment_method,
            transaction_reference=generate_reference(),
            status='pending'
        )
        db.session.add(new_donation)
        
        # Débiter le portefeuille
        transaction = update_wallet_balance(user.id, amount, 'withdrawal', f'Don à la campagne: {campaign.title}')
        
        # Mettre à jour la campagne
        campaign.current_amount += amount
        new_donation.status = 'completed'
        
        db.session.commit()
        
        flash(f'Merci pour votre don de {amount:.2f} €!', 'success')
        return redirect(url_for('campaign_detail', campaign_id=campaign.id))
    
    return render_template('campaigns/donate.html', campaign=campaign, wallet=wallet)


# API pour le portefeuille
@app.route('/api/wallet/balance')
@login_required
def api_wallet_balance():
    wallet = Wallet.query.filter_by(user_id=session['user_id']).first()
    if not wallet:
        return jsonify({'error': 'Wallet not found'}), 404
    return jsonify({'balance': wallet.balance})

@app.route('/api/wallet/transactions')
@login_required
def api_wallet_transactions():
    wallet = Wallet.query.filter_by(user_id=session['user_id']).first()
    if not wallet:
        return jsonify({'error': 'Wallet not found'}), 404
    
    transactions = Transaction.query.filter_by(wallet_id=wallet.id)\
        .order_by(Transaction.created_at.desc()).all()
    
    transactions_data = [{
        'id': t.id,
        'amount': t.amount,
        'type': t.transaction_type,
        'reference': t.reference,
        'status': t.status,
        'date': t.created_at.isoformat(),
        'description': t.description
    } for t in transactions]
    
    return jsonify({'transactions': transactions_data})


@app.route('/tontine/<int:tontine_id>/remove_member', methods=['POST'])
@login_required
def remove_member(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    user_id = request.form.get('user_id')

    if not user_id:
        flash("ID utilisateur manquant", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    # Vérifier les permissions avec current_user (plus sûr que session['user_id'])
    if current_user.id != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    # Empêcher de retirer le créateur
    if int(user_id) == tontine.creator_id:
        flash("Impossible de retirer le créateur", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    # Supprimer le membre
    membership = UserTontine.query.filter_by(user_id=user_id, tontine_id=tontine.id).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash("Membre retiré avec succès", "success")
    else:
        flash("Membre non trouvé", "warning")

    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

@app.route('/tontine/<int:tontine_id>/edit', methods=['POST'])
@login_required
def edit_tontine(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)

    # Vérifier les permissions avec current_user
    if current_user.id != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    try:
        # Mettre à jour les informations
        tontine.name = request.form.get('name')
        tontine.description = request.form.get('description')
        tontine.amount_per_member = float(request.form.get('amount'))
        tontine.frequency = request.form.get('frequency')
        tontine.max_members = int(request.form.get('max_members'))

        db.session.commit()
        flash("Tontine mise à jour avec succès", "success")
    except Exception as e:
        db.session.rollback()
        flash("Une erreur est survenue lors de la mise à jour.", "danger")
        app.logger.error(f"Erreur mise à jour tontine: {e}")

    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

@app.route('/tontine/<int:tontine_id>/close', methods=['POST'])
@login_required
def close_tontine(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier les permissions
    if current_user.id != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    tontine.is_active = False
    db.session.commit()
    flash("Tontine clôturée avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))


@app.route('/tontine/<int:tontine_id>/reopen', methods=['POST'])
@login_required
def reopen_tontine(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier les permissions
    if current_user.id != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    tontine.is_active = True
    db.session.commit()
    flash("Tontine réouverte avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))


@app.route('/tontine/<int:tontine_id>/create_cycle', methods=['POST'])
@login_required
def create_cycle(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier les permissions
    if current_user.id != tontine.creator_id and not getattr(current_user, 'is_admin', False):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Créer le nouveau cycle
    try:
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
    except (ValueError, TypeError):
        flash("Dates invalides. Veuillez entrer une date valide au format AAAA-MM-JJ.", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))

    new_cycle = TontineCycle(
        tontine_id=tontine.id,
        start_date=start_date,
        end_date=end_date
    )
    
    db.session.add(new_cycle)
    db.session.commit()

    # ✅ Notifier les membres
    notify_tontine_members(
        tontine_id,
        f"Un nouveau cycle a commencé pour la tontine {tontine.name}",
        exclude_user_id=current_user.id
    )

    flash("Nouveau cycle créé avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

# Routes pour le forum
@app.route('/forum')
def forum_home():
    # Exemple de données simulées (adapter à ta vraie structure)
    categories = [
        {
            "slug": "investissements",
            "name": "Investissements",
            "description": "Discussion autour des investissements.",
            "topics": [
                {"slug": "topic1", "title": "Premier sujet", "updated_at": datetime(2025,7,8,10,0), "user": {"username": "alice", "profile_picture_url": "/static/alice.jpg"}},
                {"slug": "topic2", "title": "Deuxième sujet", "updated_at": datetime(2025,7,7,9,0), "user": {"username": "bob", "profile_picture_url": "/static/bob.jpg"}},
            ]
        },
        # autres catégories...
    ]

    # Trier les topics dans chaque catégorie par updated_at décroissant
    for category in categories:
        category["topics"] = sorted(category["topics"], key=lambda t: t["updated_at"], reverse=True)
        category["topics_count"] = len(category["topics"])
        category["last_topic"] = category["topics"][0] if category["topics"] else None

    # Autres variables que tu passes au template
    recent_topics = []  # préparer tes sujets récents
    popular_topics = []  # préparer tes sujets populaires

    return render_template('forum/index.html',
                           categories=categories,
                           recent_topics=recent_topics,
                           popular_topics=popular_topics)


@app.route('/forum/<category_slug>')
def forum_category(category_slug):
    category = ForumCategory.query.filter_by(slug=category_slug).first_or_404()
    topics = ForumTopic.query.filter_by(category_id=category.id)\
        .order_by(ForumTopic.is_pinned.desc(), ForumTopic.updated_at.desc())\
        .all()
    
    return render_template('forum/category.html',
                         category=category,
                         topics=topics)

@app.route('/forum/<category_slug>/<topic_slug>', methods=['GET', 'POST'])
@login_required
def forum_topic(category_slug, topic_slug):
    topic = ForumTopic.query.filter_by(slug=topic_slug).first_or_404()
    
    # Incrémenter le compteur de vues
    topic.views += 1
    db.session.commit()
    
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash('Le message ne peut pas être vide', 'danger')
        else:
            new_post = ForumPost(
                content=content,
                topic_id=topic.id,
                user_id=current_user.id
            )
            db.session.add(new_post)
            
            # Mettre à jour la date de modification du sujet
            topic.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash('Votre message a été publié', 'success')
            return redirect(url_for('forum_topic', category_slug=category_slug, topic_slug=topic_slug))
    
    # Pagination des messages
    page = request.args.get('page', 1, type=int)
    posts = ForumPost.query.filter_by(topic_id=topic.id)\
        .order_by(ForumPost.created_at.asc())\
        .paginate(page=page, per_page=10)
    
    return render_template('forum/topic.html',
                         topic=topic,
                         posts=posts)

@app.route('/forum/new-topic', methods=['GET', 'POST'])
@login_required
def new_topic():
    if request.method == 'POST':
        title = request.form.get('title')
        slug = slugify(title)
        content = request.form.get('content')
        category_id = request.form.get('category_id')
        
        if not title or not content or not category_id:
            flash('Veuillez remplir tous les champs', 'danger')
        else:
            # Créer un slug à partir du titre
            slug = slugify(title)
            if ForumTopic.query.filter_by(slug=slug).first():
                slug = f"{slug}-{int(time.time())}"
            
            new_topic = ForumTopic(
                title=title,
                content=content,
                category_id=category_id,
                user_id=current_user.id,
                slug=slug
            )
            
            db.session.add(new_topic)
            
            # Créer le premier message
            first_post = ForumPost(
                content=content,
                topic_id=new_topic.id,
                user_id=current_user.id,
                is_first_post=True
            )
            db.session.add(first_post)
            
            db.session.commit()
            
            flash('Votre sujet a été créé avec succès', 'success')
            return redirect(url_for('forum_topic', 
                                 category_slug=new_topic.category.slug,
                                 topic_slug=new_topic.slug))
    
    categories = ForumCategory.query.filter_by(is_active=True).all()
    return render_template('forum/new_topic.html',
                         categories=categories)

@app.route('/forum/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = ForumPost.query.get_or_404(post_id)
    
    # Vérifier si l'utilisateur a déjà liké ce post
    existing_like = ForumLike.query.filter_by(
        post_id=post_id,
        user_id=current_user.id
    ).first()
    
    if existing_like:
        db.session.delete(existing_like)
        action = 'unliked'
    else:
        new_like = ForumLike(
            post_id=post_id,
            user_id=current_user.id
        )
        db.session.add(new_like)
        action = 'liked'
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'action': action,
        'like_count': post.likes.count()
    })

@app.route('/forum/users')
@login_required
def forum_users():
    # Liste des utilisateurs avec le plus d'activité
    active_users = User.query\
        .outerjoin(ForumTopic, ForumTopic.user_id == User.id)\
        .outerjoin(ForumPost, ForumPost.user_id == User.id)\
        .group_by(User.id)\
        .order_by(db.func.count(ForumTopic.id).desc(), db.func.count(ForumPost.id).desc())\
        .limit(20)\
        .all()
    
    return render_template('forum/users.html',
                         active_users=active_users)

@app.route('/forum/users/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get_or_404(user_id)
    
    if user_to_follow.id == current_user.id:
        return jsonify({'success': False, 'error': "Vous ne pouvez pas vous suivre vous-même"})
    
    existing_follow = UserFollow.query.filter_by(
        follower_id=current_user.id,
        followed_id=user_id
    ).first()
    
    if existing_follow:
        db.session.delete(existing_follow)
        action = 'unfollowed'
    else:
        new_follow = UserFollow(
            follower_id=current_user.id,
            followed_id=user_id
        )
        db.session.add(new_follow)
        action = 'followed'
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'action': action,
        'follower_count': UserFollow.query.filter_by(followed_id=user_id).count()
    })

@app.route('/tontine/select_beneficiary', methods=['POST'])
@login_required
def post_select_beneficiary():
    cycle_id = request.form.get('cycle_id')
    beneficiary_id = request.form.get('beneficiary_id')
    amount_received = float(request.form.get('amount_received'))
    
    cycle = TontineCycle.query.get_or_404(cycle_id)
    tontine = Tontine.query.get_or_404(cycle.tontine_id)
    
    # Vérifier les permissions
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    # Mettre à jour le cycle
    cycle.beneficiary_id = beneficiary_id
    cycle.is_completed = True
    
    # Créer une transaction pour le bénéficiaire
    beneficiary_wallet = Wallet.query.filter_by(user_id=beneficiary_id).first()
    if beneficiary_wallet:
        transaction = Transaction(
            wallet_id=beneficiary_wallet.id,
            amount=amount_received,
            transaction_type='tontine_payout',
            reference=f'TONTINE-{cycle.tontine_id}-{cycle.id}',
            status='completed',
            description=f'Gain de tontine pour le cycle {cycle.id}'
        )
        beneficiary_wallet.balance += amount_received
        db.session.add(transaction)
    
    db.session.commit()
    flash("Bénéficiaire sélectionné avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
@app.route('/tontines/<int:tontine_id>/chat')
@login_required
def get_chat_history(tontine_id):
    messages = ChatMessage.query.filter_by(tontine_id=tontine_id)\
        .order_by(ChatMessage.timestamp.asc())\
        .limit(100)\
        .all()
    return jsonify([{
        'sender': msg.user.username,
        'message': msg.content,
        'timestamp': msg.timestamp.isoformat(),
        'avatar': msg.user.profile_picture_url
    } for msg in messages])

# Gestion des événements Socket.IO
@socketio.on('join')
def handle_join(data):
    join_room(f"tontine_{data['room']}")
    emit('status', {'msg': f"{data['username']} a rejoint la discussion"}, room=f"tontine_{data['room']}")

from flask_login import current_user
from flask_socketio import emit, disconnect
from datetime import datetime

@socketio.on('message')
def handle_message(data):
    # Vérifie que l'utilisateur est connecté
    if not current_user.is_authenticated:
        disconnect()
        return

    tontine_id = data['room']
    content = data['message']
    timestamp = datetime.utcnow()

    # Sauvegarder le message en base de données
    new_message = ChatMessage(
        tontine_id=tontine_id,
        user_id=current_user.id,
        content=content,
        timestamp=timestamp
    )
    db.session.add(new_message)
    db.session.commit()

    # Envoyer le message à tous les membres de la room
    emit('new_message', {
        'sender': current_user.username,
        'message': content,
        'timestamp': timestamp.isoformat(),
        'avatar': current_user.profile_picture_url,
        'user_id': current_user.id
    }, room=f"tontine_{tontine_id}")

    # Récupérer les infos de la tontine (si elle existe)
    tontine = Tontine.query.get(tontine_id)
    tontine_name = tontine.name if tontine else "Tontine inconnue"

    # Envoyer une notification aux autres utilisateurs connectés (sauf l'émetteur)
    emit('notification', {
        'sender': current_user.username,
        'tontine_id': tontine_id,
        'tontine_name': tontine_name,
        'message': content,
        'timestamp': timestamp.isoformat()
    }, broadcast=True, include_self=False)


# Gestion des erreurs
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# Commandes CLI
@app.cli.command('initdb')
def initdb_command():
    """Initialise la base de données"""
    db.create_all()
    print('Base de données initialisée')

@app.cli.command('create-admin')
def create_admin_command():
    """Crée un utilisateur administrateur"""
    username = input("Nom d'utilisateur: ")
    email = input("Email: ")
    password = input("Mot de passe: ")
    
    hashed_password = generate_password_hash(password)
    admin = User(
        public_id=str(uuid.uuid4()),
        username=username,
        email=email,
        password=hashed_password,
        admin=True,
        verified=True
    )
    
    db.session.add(admin)
    db.session.commit()
    print(f'Administrateur {username} créé avec succès')
    

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Port par défaut = 5000
    socketio.run(app, host="0.0.0.0", port=port)
