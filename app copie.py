"""
app.py - Application principale pour le système de tontine et collecte de fonds
"""
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import uuid
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

# Modèles de données

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

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    balance = db.Column(db.Float, default=0.0)
    last_transaction = db.Column(db.DateTime)
    transactions = db.relationship('Transaction', backref='wallet', lazy='dynamic')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'))
    amount = db.Column(db.Float)
    transaction_type = db.Column(db.String(20))  # deposit, withdrawal, payment, etc.
    reference = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))

class Tontine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    amount_per_member = db.Column(db.Float)
    frequency = db.Column(db.String(20))  # daily, weekly, monthly
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    max_members = db.Column(db.Integer)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    members = db.relationship('UserTontine', back_populates='tontine')
    cycles = db.relationship('TontineCycle', back_populates='tontine')

class UserTontine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tontine_id = db.Column(db.Integer, db.ForeignKey('tontine.id'))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relations
    user = db.relationship('User', back_populates='tontines')
    tontine = db.relationship('Tontine', back_populates='members')
    contributions = db.relationship('Contribution', back_populates='user_tontine')

class TontineCycle(db.Model):
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
    active_tontines = Tontine.query.filter_by(is_active=True).order_by(Tontine.created_at.desc()).limit(4).all()
    active_campaigns = FundraisingCampaign.query.filter_by(is_active=True).order_by(FundraisingCampaign.start_date.desc()).limit(4).all()
    return render_template('index.html', tontines=active_tontines, campaigns=active_campaigns)
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
@app.route('/tontines/<int:tontine_id>')
def tontine_detail(tontine_id):
    tontine = Tontine.query.get_or_404(tontine_id)
    user_id = session.get('user_id')
    
    # Récupérer le créateur
    creator = User.query.get(tontine.creator_id)
    
    # Récupérer les membres liés à la tontine
    memberships = UserTontine.query.filter_by(tontine_id=tontine.id).all()
    members_count = len(memberships)

    # Récupérer les cycles triés par date décroissante
    cycles = TontineCycle.query.filter_by(tontine_id=tontine.id).order_by(TontineCycle.start_date.desc()).all()

    # Récupérer les bénéficiaires des cycles
    beneficiary_ids = {cycle.beneficiary_id for cycle in cycles if cycle.beneficiary_id}
    beneficiaries = User.query.filter(User.id.in_(beneficiary_ids)).all()
    beneficiaries_dict = {user.id: user for user in beneficiaries}

    # Vérifier si l'utilisateur connecté est membre
    is_member = False
    is_creator = False
    is_admin = False
    current_user = None
    
    if user_id:
        current_user = User.query.get(user_id)
        is_member = any(m.user_id == user_id for m in memberships)
        is_creator = (user_id == tontine.creator_id)
        is_admin = current_user.admin if current_user else False

    # Calculer les contributions totales par membre
    contributions = {}
    for m in memberships:
        total = sum(c.amount for c in m.contributions)  # suppose que Usedef add_memberrTontine a relation contributions
        contributions[m.user_id] = total

    return render_template(
        'tontines/detail.html',
        tontine=tontine,
        members_count=members_count,
        memberships=memberships,
        contributions=contributions,
        cycles=cycles,
        is_member=is_member,
        is_creator=is_creator,
        is_admin=is_admin,
        current_user=current_user,
        creator=creator,
        beneficiaries=beneficiaries_dict,
        datetime=datetime  # Pour utilisation dans le template
    )


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
def select_beneficiary():
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
    app.run(debug=True)
