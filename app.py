import os
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
from PIL import Image
import numpy as np

from models import db, User, Item, Message, Conversation

# Configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nhce-lost-found-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{BASE_DIR / "database.db"}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

socketio = SocketIO(app, cors_allowed_origins="*")

# Create upload folder
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def cleanup_expired_items():
    """Delete items older than 7 days"""
    expired = Item.query.filter(Item.expires_at < datetime.utcnow()).all()
    for item in expired:
        if item.image_path:
            image_file = UPLOAD_FOLDER / item.image_path
            if image_file.exists():
                image_file.unlink()
        db.session.delete(item)
    db.session.commit()


def image_to_vector(image_path, size=(128, 128)):
    """Convert image to feature vector for matching"""
    with Image.open(image_path).convert("RGB") as img:
        img = img.resize(size)
        arr = np.asarray(img, dtype="float32") / 255.0
        return arr.reshape(-1)


def cosine_similarity(a, b):
    if a.size == 0 or b.size == 0:
        return 0.0
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-8
    return float(np.dot(a, b) / denom)


# ==================== AUTH ROUTES ====================

@app.route('/')
def home():
    cleanup_expired_items()
    recent_lost = Item.query.filter_by(item_type='lost', status='active').order_by(Item.created_at.desc()).limit(6).all()
    recent_found = Item.query.filter_by(item_type='found', status='active').order_by(Item.created_at.desc()).limit(6).all()
    return render_template('home.html', recent_lost=recent_lost, recent_found=recent_found)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        department = request.form.get('department', '').strip()
        year = request.form.get('year', '').strip()
        
        # Validation
        if not all([username, email, password, full_name]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create user
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            department=department,
            year=year
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        user = User.query.filter(
            (User.username == username) | (User.email == username.lower())
        ).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(next_page or url_for('home'))
        
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# ==================== ITEM ROUTES ====================

@app.route('/items')
def items_list():
    cleanup_expired_items()
    item_type = request.args.get('type', 'all')
    category = request.args.get('category', 'all')
    search = request.args.get('search', '').strip()
    
    query = Item.query.filter_by(status='active')
    
    if item_type in ['lost', 'found']:
        query = query.filter_by(item_type=item_type)
    
    if category != 'all':
        query = query.filter_by(category=category)
    
    if search:
        query = query.filter(
            (Item.title.ilike(f'%{search}%')) |
            (Item.description.ilike(f'%{search}%')) |
            (Item.color.ilike(f'%{search}%')) |
            (Item.brand.ilike(f'%{search}%'))
        )
    
    items = query.order_by(Item.created_at.desc()).all()
    
    categories = ['bag', 'purse', 'wallet', 'phone', 'keys', 'laptop', 'books', 'id_card', 'jewelry', 'other']
    
    return render_template('items.html', items=items, categories=categories, 
                          current_type=item_type, current_category=category, search=search)


@app.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    similar_items = []
    
    # Find similar items by image matching
    if item.image_path:
        try:
            query_path = UPLOAD_FOLDER / item.image_path
            if query_path.exists():
                query_vec = image_to_vector(query_path)
                
                # Get opposite type items for matching
                opposite_type = 'found' if item.item_type == 'lost' else 'lost'
                candidates = Item.query.filter_by(item_type=opposite_type, status='active').all()
                
                for candidate in candidates:
                    if candidate.image_path and candidate.id != item.id:
                        cand_path = UPLOAD_FOLDER / candidate.image_path
                        if cand_path.exists():
                            try:
                                cand_vec = image_to_vector(cand_path)
                                score = cosine_similarity(query_vec, cand_vec)
                                if score > 0.7:  # Threshold for similarity
                                    similar_items.append({'item': candidate, 'score': round(score * 100, 1)})
                            except:
                                pass
                
                similar_items.sort(key=lambda x: x['score'], reverse=True)
                similar_items = similar_items[:5]
        except:
            pass
    
    return render_template('item_detail.html', item=item, similar_items=similar_items)


@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_item():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        item_type = request.form.get('item_type', '').strip()
        location = request.form.get('location', '').strip()
        date_str = request.form.get('date_occurred', '').strip()
        color = request.form.get('color', '').strip()
        brand = request.form.get('brand', '').strip()
        
        if not all([title, description, category, item_type]):
            flash('Please fill in all required fields.', 'error')
            return render_template('post_item.html')
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                image_filename = timestamp + filename
                file.save(UPLOAD_FOLDER / image_filename)
        
        # Parse date
        date_occurred = None
        if date_str:
            try:
                date_occurred = datetime.strptime(date_str, '%Y-%m-%d').date()
            except:
                pass
        
        item = Item(
            title=title,
            description=description,
            category=category,
            item_type=item_type,
            location=location,
            date_occurred=date_occurred,
            image_path=image_filename,
            color=color,
            brand=brand,
            user_id=current_user.id
        )
        
        db.session.add(item)
        db.session.commit()
        
        flash(f'Your {item_type} item has been posted!', 'success')
        return redirect(url_for('item_detail', item_id=item.id))
    
    categories = ['bag', 'purse', 'wallet', 'phone', 'keys', 'laptop', 'books', 'id_card', 'jewelry', 'other']
    return render_template('post_item.html', categories=categories)


@app.route('/item/<int:item_id>/resolve', methods=['POST'])
@login_required
def resolve_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        flash('You can only resolve your own items.', 'error')
        return redirect(url_for('item_detail', item_id=item_id))
    
    item.status = 'resolved'
    db.session.commit()
    flash('Item marked as resolved!', 'success')
    return redirect(url_for('my_items'))


@app.route('/item/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        flash('You can only delete your own items.', 'error')
        return redirect(url_for('item_detail', item_id=item_id))
    
    if item.image_path:
        image_file = UPLOAD_FOLDER / item.image_path
        if image_file.exists():
            image_file.unlink()
    
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted.', 'success')
    return redirect(url_for('my_items'))


@app.route('/my-items')
@login_required
def my_items():
    items = Item.query.filter_by(user_id=current_user.id).order_by(Item.created_at.desc()).all()
    return render_template('my_items.html', items=items)


# ==================== PROFILE ROUTES ====================

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    items = Item.query.filter_by(user_id=user_id, status='active').order_by(Item.created_at.desc()).all()
    return render_template('profile.html', user=user, items=items)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', '').strip()
        current_user.phone = request.form.get('phone', '').strip()
        current_user.department = request.form.get('department', '').strip()
        current_user.year = request.form.get('year', '').strip()
        
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))
    
    return render_template('edit_profile.html')


# ==================== CHAT ROUTES ====================

@app.route('/messages')
@login_required
def messages():
    # Get all conversations for current user
    conversations = Conversation.query.filter(
        (Conversation.user1_id == current_user.id) | 
        (Conversation.user2_id == current_user.id)
    ).order_by(Conversation.last_message_at.desc()).all()
    
    return render_template('messages.html', conversations=conversations)


@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    if user_id == current_user.id:
        return redirect(url_for('messages'))
    
    other_user = User.query.get_or_404(user_id)
    item_id = request.args.get('item_id', type=int)
    
    # Find or create conversation
    conversation = Conversation.query.filter(
        ((Conversation.user1_id == current_user.id) & (Conversation.user2_id == user_id)) |
        ((Conversation.user1_id == user_id) & (Conversation.user2_id == current_user.id))
    ).first()
    
    if not conversation:
        conversation = Conversation(
            user1_id=current_user.id,
            user2_id=user_id,
            item_id=item_id
        )
        db.session.add(conversation)
        db.session.commit()
    
    # Get messages between users
    chat_messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    unread = Message.query.filter_by(sender_id=user_id, receiver_id=current_user.id, is_read=False).all()
    for msg in unread:
        msg.is_read = True
    db.session.commit()
    
    return render_template('chat.html', other_user=other_user, messages=chat_messages, conversation=conversation)


@app.route('/api/send-message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()
    
    if not receiver_id or not content:
        return jsonify({'error': 'Invalid data'}), 400
    
    message = Message(
        content=content,
        sender_id=current_user.id,
        receiver_id=receiver_id
    )
    db.session.add(message)
    
    # Update conversation timestamp
    conversation = Conversation.query.filter(
        ((Conversation.user1_id == current_user.id) & (Conversation.user2_id == receiver_id)) |
        ((Conversation.user1_id == receiver_id) & (Conversation.user2_id == current_user.id))
    ).first()
    
    if conversation:
        conversation.last_message_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': {
            'id': message.id,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%I:%M %p'),
            'sender_id': message.sender_id
        }
    })


# ==================== SOCKET.IO EVENTS ====================

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    join_room(room)


@socketio.on('send_message')
def handle_message(data):
    room = data.get('room')
    message_data = {
        'content': data.get('content'),
        'sender_id': current_user.id,
        'sender_name': current_user.full_name,
        'timestamp': datetime.now().strftime('%I:%M %p')
    }
    emit('receive_message', message_data, room=room)


# ==================== IMAGE MATCHING ROUTE ====================

@app.route('/match', methods=['GET', 'POST'])
@login_required
def match_item():
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('Please upload an image.', 'error')
            return render_template('match.html', matches=[])
        
        file = request.files['image']
        if not file or not file.filename:
            flash('Please select an image file.', 'error')
            return render_template('match.html', matches=[])
        
        try:
            # Process uploaded image
            img = Image.open(file.stream).convert("RGB")
            img = img.resize((128, 128))
            query_vec = (np.asarray(img, dtype="float32") / 255.0).reshape(-1)
        except:
            flash('Could not process the image.', 'error')
            return render_template('match.html', matches=[])
        
        # Find matching items
        matches = []
        items = Item.query.filter_by(status='active').all()
        
        for item in items:
            if item.image_path:
                item_path = UPLOAD_FOLDER / item.image_path
                if item_path.exists():
                    try:
                        item_vec = image_to_vector(item_path)
                        score = cosine_similarity(query_vec, item_vec)
                        matches.append({
                            'item': item,
                            'score': round(score * 100, 1)
                        })
                    except:
                        pass
        
        matches.sort(key=lambda x: x['score'], reverse=True)
        matches = matches[:10]
        
        return render_template('match.html', matches=matches)
    
    return render_template('match.html', matches=[])


# ==================== INITIALIZATION ====================

def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized!")


if __name__ == "__main__":
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
else:
    # For production (Gunicorn)
    init_db()
