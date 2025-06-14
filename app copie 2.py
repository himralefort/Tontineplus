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
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Configuration de l'application
app = Flask(__name__)
app.config['SECRET_KEY'] = '6d9348c846d2c517894e87b972b517c9'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tontine.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
login_manager = LoginManager()
login_manager.login_view = 'login'  # nom de la vue login
login_manager.init_app(app)

# Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)
# Créer les dossiers nécessaires s'ils n'existent pas
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures'), exist_ok=True)
# Modèles de données

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



class User(db.Model):
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

class Tontine(db.Model):
    __tablename__ = 'tontine'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    amount_per_member = db.Column(db.Float)
    frequency = db.Column(db.String(20))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    max_members = db.Column(db.Integer)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relations
    members = db.relationship('UserTontine', back_populates='tontine')
    cycles = db.relationship('TontineCycle', back_populates='tontine')
    # suppression de la relation contributions car pas de FK directe

    @property
    def current_members(self):
        return len([m for m in self.members if m.is_active])

    @property
    def contributions(self):
        # Agrège toutes les contributions via les cycles
        return [contribution for cycle in self.cycles for contribution in cycle.contributions]


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

# Décorateurs personnalisés
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user.admin:
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes d'authentification
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Pour utilisateur connecté
        user_tontines = db.session.query(Tontine).join(
            UserTontine, UserTontine.tontine_id == Tontine.id
        ).filter(
            Tontine.is_active == True,
            UserTontine.user_id == current_user.id,
            UserTontine.is_active == True
        ).order_by(Tontine.created_at.desc()).limit(4).all()
        
        wallet = Wallet.query.filter_by(user_id=current_user.id).first()
        transactions = []
        if wallet:
            transactions = Transaction.query.filter_by(wallet_id=wallet.id)\
                .order_by(Transaction.created_at.desc()).limit(5).all()
        
        return render_template('index.html',
                           user_tontines=user_tontines,
                           transactions=transactions)
    else:
        # Pour visiteur non connecté
        return render_template('index.html')
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')

        # Vérification des champs requis
        if not username or not email or not password:
            flash('Veuillez remplir tous les champs obligatoires', 'danger')
            return redirect(url_for('register'))

        # Validation unicité username et email
        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà pris", 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé", 'danger')
            return redirect(url_for('register'))

        # Hashage du mot de passe
        hashed_password = generate_password_hash(password)

        # Création de l'utilisateur
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
        db.session.commit()

        # Création du portefeuille lié à l'utilisateur
        new_wallet = Wallet(user_id=new_user.id)
        db.session.add(new_wallet)

        # ** Gestion invitation tontine **
        token = session.pop('invite_token', None)  # Récupère et supprime le token en session
        if token:
            invitation = TontineInvitation.query.filter_by(token=token, accepted=False).first()
            if invitation:
                # Ajouter le nouvel utilisateur comme membre
                existing_membership = TontineMember.query.filter_by(
                    user_id=new_user.id, tontine_id=invitation.tontine_id).first()
                if not existing_membership:
                    membership = TontineMember(user_id=new_user.id, tontine_id=invitation.tontine_id)
                    db.session.add(membership)
                # Marquer invitation comme acceptée
                invitation.accepted = True

        db.session.commit()

        flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Identifiants incorrects', 'danger')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.admin
        
        flash('Connexion réussie!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('auth/login.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
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
@login_required
def logout():
    session.clear()
    flash('Vous avez été déconnecté avec succès', 'success')
    return redirect(url_for('index'))
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        flash("Utilisateur non trouvé", "danger")
        return redirect(url_for('logout'))
    
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    
    # Tontines de l'utilisateur
    user_tontines = UserTontine.query.filter_by(user_id=user.id).all()
    tontine_ids = [ut.tontine_id for ut in user_tontines]
    tontines = Tontine.query.filter(Tontine.id.in_(tontine_ids)).all() if tontine_ids else []
    
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
                           transactions=transactions)

# Routes du portefeuille
@app.route('/wallet')
@login_required
def wallet():
    user = User.query.get(session['user_id'])
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

        user = User.query.get(session['user_id'])
        transaction = update_wallet_balance(user.id, amount, 'deposit', description)

        flash(f'Dépôt de {amount:.2f} effectué avec succès. Référence: {transaction.reference}', 'success')
        return redirect(url_for('wallet'))

    return render_template('wallet/deposit.html')


@app.route('/wallet/withdraw', methods=['GET', 'POST'])
@login_required
def wallet_withdraw():
    user = User.query.get(session['user_id'])
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

# Routes de tontine
@app.route('/tontines')
def tontines_list():
    all_tontines = Tontine.query.filter_by(is_active=True).all()
    return render_template('tontines/list.html', tontines=all_tontines)
from datetime import datetime, timedelta

@app.route('/tontines/<int:tontine_id>')
def tontine_detail(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    user_id = session.get('user_id')

    # Vérifier si l'utilisateur est membre
    is_member = False
    if user_id:
        is_member = UserTontine.query.filter_by(user_id=user_id, tontine_id=tontine.id).first() is not None

    # Vérifier si l'utilisateur est le créateur ou admin
    is_creator = user_id == tontine.creator_id
    is_admin = False
    user = None
    if user_id:
        user = User.query.get(user_id)
        is_admin = user.admin if user else False

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
        current_user=user if user_id else None,
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
    user_id = session['user_id']
    
    # Vérifier que l'utilisateur est membre
    membership = UserTontine.query.filter_by(user_id=user_id, tontine_id=tontine.id).first()
    if not membership:
        flash("Vous n'êtes pas membre de cette tontine", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Trouver le cycle actif
    current_cycle = TontineCycle.query.filter_by(
        tontine_id=tontine.id,
        is_completed=False
    ).order_by(TontineCycle.start_date.desc()).first()
    
    if not current_cycle:
        flash("Aucun cycle actif pour cette tontine", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Vérifier si l'utilisateur a déjà payé pour ce cycle
    existing_payment = Contribution.query.filter_by(
        user_id=user_id,
        cycle_id=current_cycle.id
    ).first()
    
    if existing_payment:
        flash("Vous avez déjà payé pour ce cycle", "info")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Effectuer le paiement
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet or wallet.balance < tontine.amount_per_member:
        flash("Solde insuffisant dans votre portefeuille", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Créer la contribution
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
    
    # Mettre à jour le portefeuille
    transaction = update_wallet_balance(
        user_id,
        tontine.amount_per_member,
        'withdrawal',
        f'Cotisation tontine {tontine.name} - cycle {current_cycle.id}'
    )
    
    db.session.add(new_contribution)
    db.session.commit()
    
    flash("Paiement effectué avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

@app.route('/tontine/<int:cycle_id>/select_beneficiary', methods=['POST'])
@login_required
def select_beneficiary(cycle_id):
    cycle = TontineCycle.query.get_or_404(cycle_id)
    tontine = Tontine.query.get_or_404(cycle.tontine_id)
    
    # Vérifier les permissions
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    beneficiary_id = request.form.get('beneficiary_id')
    selection_method = request.form.get('selection_method', 'manual')  # 'manual' ou 'random'
    
    if selection_method == 'random':
        # Sélection aléatoire parmi les membres ayant payé
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
    
    # Vérifier que le bénéficiaire a payé pour ce cycle
    has_paid = Contribution.query.filter_by(
        user_id=beneficiary_id,
        cycle_id=cycle.id,
        status='paid'
    ).first() is not None
    
    if not has_paid:
        flash("Le bénéficiaire doit avoir payé pour ce cycle", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    # Mettre à jour le cycle
    cycle.beneficiary_id = beneficiary_id
    cycle.is_completed = True
    
    # Créditer le bénéficiaire
    amount = tontine.amount_per_member * len([m for m in tontine.members])
    beneficiary_wallet = Wallet.query.filter_by(user_id=beneficiary_id).first()
    
    if beneficiary_wallet:
        transaction = update_wallet_balance(
            beneficiary_id,
            amount,
            'deposit',
            f'Gain tontine {tontine.name} - cycle {cycle.id}'
        )
    
    db.session.commit()
    
    flash(f"Bénéficiaire sélectionné avec succès ({amount} XOF transférés)", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine.id))

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
            creator_id=session['user_id']
        )
        
        db.session.add(new_tontine)
        db.session.commit()
        
        # Ajouter le créateur comme membre
        user_tontine = UserTontine(
            user_id=session['user_id'],
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

    # Vérifie que l'utilisateur connecté est le créateur ou un admin (optionnel)
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
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


@app.route('/tontines/<int:tontine_id>/join')
@login_required
def tontine_join(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier si l'utilisateur est déjà membre
    existing_membership = UserTontine.query.filter_by(
        user_id=session['user_id'],
        tontine_id=tontine.id
    ).first()
    
    if existing_membership:
        flash('Vous êtes déjà membre de cette tontine', 'warning')
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    # Vérifier si la tontine est pleine
    current_members = UserTontine.query.filter_by(tontine_id=tontine.id).count()
    if current_members >= tontine.max_members:
        flash('Cette tontine a atteint son nombre maximum de membres', 'danger')
        return redirect(url_for('tontine_detail', tontine_id=tontine.id))
    
    # Ajouter l'utilisateur à la tontine
    new_membership = UserTontine(
        user_id=session['user_id'],
        tontine_id=tontine.id
    )
    db.session.add(new_membership)
    db.session.commit()
    
    flash('Vous avez rejoint la tontine avec succès!', 'success')
    return redirect(url_for('tontine_detail', tontine_id=tontine.id))



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



# Routes de collecte de fonds
@app.route('/campaigns')
def campaigns_list():
    all_campaigns = FundraisingCampaign.query.filter_by(is_active=True).all()
    return render_template('campaigns/list.html', campaigns=all_campaigns)


@app.route('/campaigns/<int:campaign_id>')
def campaign_detail(campaign_id):
    campaign = FundraisingCampaign.query.get_or_404(campaign_id)
    donations = Donation.query.filter_by(campaign_id=campaign.id, status='completed')\
        .order_by(Donation.created_at.desc()).all()
    progress = (campaign.current_amount / campaign.target_amount) * 100 if campaign.target_amount > 0 else 0
    creator = User.query.get(campaign.creator_id)

    days_remaining = (campaign.end_date - datetime.utcnow()).days if campaign.end_date else None

    return render_template(
        'campaigns/detail.html',
        campaign=campaign,
        donations=donations,
        progress=progress,
        creator=creator,
        days_remaining=days_remaining
    )


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

@app.route('/campaigns/create', methods=['GET', 'POST'])
@login_required
def campaign_create():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        target_amount = float(request.form.get('target_amount'))
        end_date_str = request.form.get('end_date')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
        
        # Gestion de l'image
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                image_url = url_for('static', filename=f'uploads/{unique_filename}')
        
        new_campaign = FundraisingCampaign(
            title=title,
            description=description,
            target_amount=target_amount,
            creator_id=session['user_id'],
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
    user = User.query.get(session['user_id'])
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        message = request.form.get('message')
        is_anonymous = request.form.get('is_anonymous') == 'on'
        payment_method = 'wallet'  # Pour simplifier, on suppose que le paiement se fait via le portefeuille
        
        if amount <= 0:
            flash('Le montant doit être supérieur à zéro', 'danger')
            return redirect(url_for('campaign_donate', campaign_id=campaign.id))
        
        if wallet.balance < amount:
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
        
        # Mettre à jour le montant de la campagne
        campaign.current_amount += amount
        new_donation.status = 'completed'
        
        db.session.commit()
        
        flash(f'Merci pour votre don de {amount}!', 'success')
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
    
    # Vérifier les permissions
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Vérifier que l'utilisateur n'est pas le créateur
    if user_id == tontine.creator_id:
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
    
    # Vérifier les permissions
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Mettre à jour les informations
    tontine.name = request.form.get('name')
    tontine.description = request.form.get('description')
    tontine.amount_per_member = float(request.form.get('amount'))
    tontine.frequency = request.form.get('frequency')
    tontine.max_members = int(request.form.get('max_members'))
    
    db.session.commit()
    flash("Tontine mise à jour avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

@app.route('/tontine/<int:tontine_id>/close', methods=['POST'])
@login_required
def close_tontine(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    
    # Vérifier les permissions
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
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
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
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
    if session['user_id'] != tontine.creator_id and not session.get('is_admin'):
        flash("Action non autorisée", "danger")
        return redirect(url_for('tontine_detail', tontine_id=tontine_id))
    
    # Créer le nouveau cycle
    start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
    end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
    
    new_cycle = TontineCycle(
        tontine_id=tontine.id,
        start_date=start_date,
        end_date=end_date
    )
    
    db.session.add(new_cycle)
    db.session.commit()
    flash("Nouveau cycle créé avec succès", "success")
    return redirect(url_for('tontine_detail', tontine_id=tontine_id))

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

@app.route('/tontine/<int:tontine_id>/chat/history')
@login_required
def get_chat_history(tontine_id):
    # Implémentez cette fonction pour retourner l'historique des messages
    # Exemple basique :
    messages = []  # À remplacer par une requête à votre base de données
    return jsonify(messages)

# Handlers Socket.IO
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    send({
        'sender': 'System',
        'message': f"{data['username']} a rejoint le chat",
        'timestamp': datetime.utcnow().isoformat()
    }, to=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    # Sauvegardez le message en base de données ici si nécessaire
    send({
        'sender': data['sender'],
        'message': data['message'],
        'timestamp': data['timestamp']
    }, to=room)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=3000)

