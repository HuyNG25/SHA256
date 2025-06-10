import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, g
import hashlib
from datetime import datetime
import uuid # Để tạo tên file duy nhất

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here_change_this_in_production_for_security' # THAY ĐỔI CHUỖI NÀY!
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn kích thước file 16MB

# Tạo thư mục uploads nếu chưa tồn tại
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Database setup ---
# Lấy kết nối database, đảm bảo chỉ có một kết nối cho mỗi request
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('database.db')
        g.db.row_factory = sqlite3.Row  # Cho phép truy cập cột bằng tên
    return g.db

# Đóng kết nối database sau mỗi request
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Khởi tạo hoặc tạo lại các bảng database
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,          -- Tên file gốc
                sha256 TEXT NOT NULL,
                stored_filename TEXT NOT NULL,   -- Tên file thực tế được lưu trên server (duy nhất)
                upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS received_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_user_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,    -- Tên file gốc
                stored_filename TEXT NOT NULL,      -- Tên file thực tế (để tải xuống)
                sha256 TEXT NOT NULL,
                receive_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (receiver_user_id) REFERENCES users(id),
                FOREIGN KEY (sender_user_id) REFERENCES users(id)
            );
        ''')
        db.commit()

# Khởi tạo DB khi ứng dụng chạy lần đầu
with app.app_context():
    init_db()

# --- Middleware để kiểm tra đăng nhập ---
@app.before_request
def check_logged_in():
    # Các trang không yêu cầu đăng nhập
    if request.endpoint in ['login', 'register', 'static']:
        return
    
    # Nếu không có user_id trong session và không phải là trang được phép, chuyển hướng đến trang đăng nhập
    if 'user_id' not in session and request.endpoint != 'dashboard': # dashboard cần kiểm tra riêng
        flash('Bạn cần đăng nhập để truy cập trang này.', 'error')
        return redirect(url_for('login'))

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login')) # Chuyển hướng thẳng tới trang đăng nhập

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not fullname or not email or not username or not password or not confirm_password:
            flash('Vui lòng điền đầy đủ thông tin.', 'error')
        elif password != confirm_password:
            flash('Mật khẩu và xác nhận mật khẩu không khớp.', 'error')
        else:
            db = get_db()
            cursor = db.cursor()
            try:
                # Dùng SHA256 để hash mật khẩu (nên dùng Bcrypt trong thực tế cho bảo mật cao hơn)
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                cursor.execute("INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)",
                               (fullname, email, username, hashed_password))
                db.commit()
                flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Tên đăng nhập hoặc Email đã tồn tại.', 'error')
    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            # So sánh mật khẩu đã hash
            hashed_password_input = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password_input == user['password']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Đăng nhập thành công!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
    return render_template('login.html')

@app.route('/dashboard', methods=('GET', 'POST'))
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()

    # --- Xử lý Upload File ---
    filename_display = None
    sha256_display = None
    if request.method == 'POST' and 'upload_file_btn' in request.form:
        if 'file' not in request.files:
            flash('Không có file nào được chọn.', 'error')
        else:
            file = request.files['file']
            if file.filename == '':
                flash('Vui lòng chọn file.', 'error')
            elif file:
                original_filename = file.filename
                file_content = file.read() # Đọc toàn bộ nội dung file để tính SHA256

                # Tính SHA-256
                sha256_hash = hashlib.sha256(file_content).hexdigest()
                
                # Tạo tên file duy nhất để lưu trữ (ví dụ: UUID + tên gốc)
                unique_filename = str(uuid.uuid4()) + "_" + original_filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Ghi nội dung file vào đường dẫn mới
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                # Lưu thông tin vào DB
                db.execute("INSERT INTO uploads (user_id, filename, sha256, stored_filename) VALUES (?, ?, ?, ?)",
                               (user_id, original_filename, sha256_hash, unique_filename))
                db.commit()

                filename_display = original_filename
                sha256_display = sha256_hash
                flash('File đã được tải lên thành công!', 'success')
        return redirect(url_for('dashboard', _anchor='upload-section')) # Chuyển hướng để xóa POST data và cuộn tới phần upload

    # --- Xử lý Gửi File ---
    if request.method == 'POST' and 'send_file_btn' in request.form:
        receiver_id = request.form.get('receiver_id')
        uploaded_file_id = request.form.get('uploaded_file_id')

        if not receiver_id or not uploaded_file_id:
            flash('Vui lòng chọn tài khoản nhận và file để gửi.', 'error')
        elif int(receiver_id) == user_id: # Không cho phép gửi cho chính mình
            flash('Bạn không thể tự gửi file cho chính mình.', 'error')
        else:
            # Lấy thông tin file gốc từ bảng uploads của người gửi
            file_info = db.execute("SELECT filename, sha256, stored_filename FROM uploads WHERE id = ? AND user_id = ?", 
                                 (uploaded_file_id, user_id)).fetchone()
            
            if file_info:
                original_filename = file_info['filename']
                sha256 = file_info['sha256']
                stored_filename = file_info['stored_filename']

                # Ghi thông tin file nhận vào DB của người nhận
                db.execute("INSERT INTO received_files (receiver_user_id, sender_user_id, original_filename, stored_filename, sha256) VALUES (?, ?, ?, ?, ?)",
                               (receiver_id, user_id, original_filename, stored_filename, sha256))
                db.commit()
                flash(f'File "{original_filename}" đã được gửi thành công!', 'success')
            else:
                flash('Không tìm thấy file để gửi hoặc bạn không có quyền gửi file này.', 'error')
        return redirect(url_for('dashboard', _anchor='send-file-section'))


    # --- Lấy dữ liệu để hiển thị ---
    # Thông tin tài khoản
    user_info = db.execute("SELECT fullname, email, username FROM users WHERE id = ?", (user_id,)).fetchone()

    # Lịch sử Upload của tài khoản hiện tại
    uploads = db.execute("SELECT filename, sha256, upload_time FROM uploads WHERE user_id = ? ORDER BY upload_time DESC", (user_id,)).fetchall()

    # Lấy danh sách các tài khoản khác để gửi file
    other_users = db.execute("SELECT id, username FROM users WHERE id != ?", (user_id,)).fetchall()
    
    # Lấy danh sách các file đã upload của người dùng hiện tại (cho mục gửi file)
    my_uploads_for_sending = db.execute("SELECT id, filename, sha256 FROM uploads WHERE user_id = ? ORDER BY upload_time DESC", (user_id,)).fetchall()

    # Lịch sử nhận file
    received_files = db.execute('''
        SELECT rf.original_filename, rf.sha256, rf.receive_time, rf.stored_filename, u.username as sender_username
        FROM received_files rf
        JOIN users u ON rf.sender_user_id = u.id
        WHERE rf.receiver_user_id = ?
        ORDER BY rf.receive_time DESC
    ''', (user_id,)).fetchall()

    return render_template('dashboard.html',
                           user_info=user_info,
                           filename_display=filename_display,
                           sha256_display=sha256_display,
                           uploads=uploads,
                           other_users=other_users,
                           my_uploads_for_sending=my_uploads_for_sending,
                           received_files=received_files)

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        flash('Bạn cần đăng nhập để tải xuống file.', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    db = get_db()

    # Kiểm tra xem người dùng có quyền tải file này không
    # (File này có phải do họ upload, hay là file họ đã nhận)
    
    # Kiểm tra trong uploads của chính họ
    uploaded_by_self = db.execute("SELECT id FROM uploads WHERE stored_filename = ? AND user_id = ?", (filename, user_id)).fetchone()
    
    # Kiểm tra trong received_files
    received_by_self = db.execute("SELECT id FROM received_files WHERE stored_filename = ? AND receiver_user_id = ?", (filename, user_id)).fetchone()

    if uploaded_by_self or received_by_self:
        # Kiểm tra file tồn tại trên hệ thống
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        else:
            flash('File không tồn tại trên máy chủ.', 'error')
    else:
        flash('Bạn không có quyền truy cập file này.', 'error')
    
    return redirect(url_for('dashboard', _anchor='received-files-section'))

@app.route('/logout_confirm')
def logout_confirm():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('logout_confirm.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)