from flask import Flask, render_template, request, jsonify, send_file, abort, session, redirect, url_for, flash
import os
import json
from werkzeug.utils import secure_filename
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-for-session'

# 설정
UPLOAD_FOLDER = 'ppt_files'
METADATA_FILE = 'ppt_metadata.json'
ALLOWED_EXTENSIONS = {'ppt', 'pptx'}
ADMIN_PASSWORD = 'admin123'  # 관리자 비밀번호
SITE_PASSWORD = 'hospital2025'  # 사이트 접근 비밀번호

# 폴더 생성
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def check_site_access():
    """사이트 접근 권한 확인"""
    return session.get('site_authenticated', False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_ppt_title(file_path):
    try:
        if file_path.endswith('.pptx'):
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                try:
                    core_xml = zip_file.read('docProps/core.xml').decode('utf-8')
                    title_match = re.search(r'<dc:title[^>]*>([^<]*)</dc:title>', core_xml, re.IGNORECASE)
                    if title_match and title_match.group(1).strip():
                        return title_match.group(1).strip()
                except:
                    pass
                
                try:
                    slide_xml = zip_file.read('ppt/slides/slide1.xml').decode('utf-8')
                    text_matches = re.findall(r'<a:t[^>]*>([^<]*)</a:t>', slide_xml)
                    if text_matches:
                        first_text = text_matches[0].strip()
                        if first_text:
                            return first_text
                except:
                    pass
        
        return os.path.splitext(os.path.basename(file_path))[0]
    
    except Exception as e:
        print(f"Error extracting title from {file_path}: {e}")
        return os.path.splitext(os.path.basename(file_path))[0]

def load_metadata():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_metadata(metadata):
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

def scan_existing_files():
    metadata = []
    
    if os.path.exists(UPLOAD_FOLDER):
        for filename in os.listdir(UPLOAD_FOLDER):
            if allowed_file(filename):
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                title = extract_ppt_title(file_path)
                
                metadata.append({
                    'filename': filename,
                    'title': title,
                    'file_size': os.path.getsize(file_path)
                })
    
    save_metadata(metadata)
    return metadata

# 사이트 접근 라우트
@app.route('/site-login')
def site_login_page():
    if check_site_access():
        return redirect(url_for('index'))
    return render_template('site_login.html')

@app.route('/site-login', methods=['POST'])
def site_login():
    password = request.form.get('password')
    if password == SITE_PASSWORD:
        session['site_authenticated'] = True
        flash('사이트 접근이 승인되었습니다.', 'success')
        return redirect(url_for('index'))
    else:
        flash('접근 비밀번호가 잘못되었습니다.', 'error')
        return redirect(url_for('site_login_page'))

@app.route('/site-logout')
def site_logout():
    session.pop('site_authenticated', None)
    session.pop('is_admin', None)
    flash('사이트에서 로그아웃되었습니다.', 'info')
    return redirect(url_for('site_login_page'))

# 메인 라우트
@app.route('/')
def index():
    if not check_site_access():
        return redirect(url_for('site_login_page'))
    return render_template('index.html', is_admin=session.get('is_admin', False))

# 관리자 라우트
@app.route('/admin/login')
def admin_login_page():
    if not check_site_access():
        return redirect(url_for('site_login_page'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    if not check_site_access():
        return redirect(url_for('site_login_page'))
        
    password = request.form.get('password')
    if password == ADMIN_PASSWORD:
        session['is_admin'] = True
        flash('관리자로 로그인되었습니다.', 'success')
        return redirect(url_for('index'))
    else:
        flash('비밀번호가 잘못되었습니다.', 'error')
        return redirect(url_for('admin_login_page'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/upload', methods=['POST'])
def admin_upload():
    if not check_site_access() or not session.get('is_admin'):
        return jsonify({'error': '권한이 필요합니다.'}), 403
    
    if 'files' not in request.files:
        return jsonify({'error': '파일이 선택되지 않았습니다.'}), 400
    
    files = request.files.getlist('files')
    uploaded_files = []
    errors = []
    
    for file in files:
        if file.filename == '':
            continue
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            counter = 1
            original_filename = filename
            while os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
                name, ext = os.path.splitext(original_filename)
                filename = f"{name}_{counter}{ext}"
                counter += 1
            
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            try:
                file.save(file_path)
                title = extract_ppt_title(file_path)
                uploaded_files.append({
                    'filename': filename,
                    'title': title,
                    'file_size': os.path.getsize(file_path)
                })
            except Exception as e:
                errors.append(f"{file.filename}: {str(e)}")
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            errors.append(f"{file.filename}: 지원하지 않는 파일 형식")
    
    if uploaded_files:
        metadata = load_metadata()
        metadata.extend(uploaded_files)
        save_metadata(metadata)
    
    return jsonify({
        'success': len(uploaded_files),
        'uploaded_files': uploaded_files,
        'errors': errors
    })

@app.route('/admin/delete/<filename>', methods=['DELETE'])
def admin_delete_file(filename):
    if not check_site_access() or not session.get('is_admin'):
        return jsonify({'error': '권한이 필요합니다.'}), 403
    
    filename = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            metadata = load_metadata()
            metadata = [item for item in metadata if item['filename'] != filename]
            save_metadata(metadata)
            return jsonify({'message': f'{filename} 파일이 삭제되었습니다.'})
        except Exception as e:
            return jsonify({'error': f'파일 삭제 중 오류: {str(e)}'}), 500
    else:
        return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

# API 라우트
@app.route('/api/files')
def get_files():
    if not check_site_access():
        return jsonify({'error': '사이트 접근 권한이 필요합니다.'}), 403
    metadata = load_metadata()
    return jsonify(metadata)

@app.route('/api/search')
def search_files():
    if not check_site_access():
        return jsonify({'error': '사이트 접근 권한이 필요합니다.'}), 403
        
    query = request.args.get('q', '').lower().strip()
    metadata = load_metadata()
    
    if not query:
        return jsonify(metadata)
    
    results = [
        item for item in metadata 
        if query in item['title'].lower() or query in item['filename'].lower()
    ]
    
    return jsonify(results)

@app.route('/api/download/<filename>')
def download_file(filename):
    if not check_site_access():
        return jsonify({'error': '사이트 접근 권한이 필요합니다.'}), 403
        
    if not allowed_file(filename):
        abort(404)
    
    file_path = os.path.join(UPLOAD_FOLDER, secure_filename(filename))
    
    if not os.path.exists(file_path):
        abort(404)
    
    return send_file(file_path, as_attachment=True)

@app.route('/api/rescan')
def rescan_files():
    if not check_site_access():
        return jsonify({'error': '사이트 접근 권한이 필요합니다.'}), 403
    metadata = scan_existing_files()
    return jsonify({
        'message': f'{len(metadata)}개 파일 스캔 완료',
        'files': metadata
    })

if __name__ == '__main__':
    scan_existing_files()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)