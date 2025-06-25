from flask import Flask, request, jsonify, send_from_directory
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import bcrypt
from datetime import datetime
from config import DATABASE_CONFIG, JWT_CONFIG
from MySQLdb.cursors import DictCursor
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
# 이미지 업로드 관련 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅   MySQL 설정
app.config.update(DATABASE_CONFIG)
mysql = MySQL(app)

# 🔐   JWT 설정
app.config["JWT_SECRET_KEY"] = JWT_CONFIG["JWT_SECRET_KEY"]
app.config["JWT_ALGORITHM"] = JWT_CONFIG["JWT_ALGORITHM"]
jwt = JWTManager(app)

@app.route('/test-db')
def test_db():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        return "DB 연결 성공!"
    except Exception as e:
        return f"DB 연결 실패: {e}"

# ✅  아이디 중복 체크 API
@app.route('/check-username', methods=['POST'])
def check_username():
    data = request.json
    username = data.get("username")
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        return jsonify({"exists": True, "message": "이미 존재하는 아이디입니다."}), 400
    else:
        return jsonify({"exists": False, "message": "사용 가능한 아이디입니다."}), 200

# 1️⃣ 🔑   회원가입 (POST /register)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")
    age = data.get("age")
    if not name or not age:
        return jsonify({"error": "이름과 나이는 필수 입력값입니다."}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (username, password, name, age)
            VALUES (%s, %s, %s, %s)
        """, (username, hashed_password, name, age))
        mysql.connection.commit()
        return jsonify({"message": "회원가입 성공"}), 201
    except:
        return jsonify({"error": "이미 존재하는 사용자입니다."}), 400
    finally:
        cursor.close()

# 2️⃣ 🔑   로그인 (POST /login)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        access_token = create_access_token(identity=str(user["id"]))
        return jsonify({
            "access_token": access_token,
            "name": user["name"],
            "age": user["age"]
        })
    else:
        return jsonify({"error": "아이디 또는 비밀번호가 틀렸습니다."}), 401

# 3️⃣ 📚   모든 소설 조회 (GET /notes)
@app.route('/notes', methods=['GET'])
def get_notes():
    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM notes")
    notes = cursor.fetchall()
    cursor.close()
    return jsonify(notes)

# 4️⃣ ✍️   소설 추가 (POST /notes)
@app.route('/notes', methods=['POST'])
@jwt_required()
def add_note():
    user_id = get_jwt_identity()
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT name FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "사용자를 찾을 수 없습니다."}), 404
    author_name = result[0]

    data = request.json
    cursor.execute("""
        INSERT INTO notes (title, content, category, image, description, author_id, author_name)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        data.get("title", ""),
        data.get("content", ""),
        data.get("category", ""),
        data.get("image", ""),
        data.get("description", ""),
        user_id,
        author_name
    ))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "소설 추가 성공"}), 201

# 5️⃣ ✍️   특정 소설 수정 (PUT /notes/<id>) - 본인만 가능
@app.route('/notes/<int:note_id>', methods=['PUT'])
@jwt_required()
def update_note(note_id):
    user_id = get_jwt_identity()
    data = request.json
    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM notes WHERE id = %s AND author_id = %s", (note_id, user_id))
    note = cursor.fetchone()
    if not note:
        cursor.close()
        return jsonify({"error": "수정 권한이 없습니다."}), 403
    cursor.execute("""
        UPDATE notes SET title = %s, content = %s, category = %s, image = %s, description = %s
        WHERE id = %s
    """, (data["title"], data["content"], data["category"], data["image"], data["description"], note_id))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "소설 수정 완료"}), 200

# 6️⃣ ❌   특정 소설 삭제 (DELETE /notes/<id>)
@app.route('/notes/<int:note_id>', methods=['DELETE'])
@jwt_required()
def delete_note(note_id):
    user_id = get_jwt_identity()

    user_id = int(user_id)
    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM notes WHERE id = %s", (note_id,))
    note = cursor.fetchone()

    if not note:
        cursor.close()
        return jsonify({"error": "소설을 찾을 수 없습니다."}), 404

    author_id = int(note["author_id"])

    if author_id != user_id:
        cursor.close()
        return jsonify({"error": "삭제 권한이 없습니다."}), 403

    cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "소설 삭제 완료"}), 200

# 7️⃣ 특정 소설 좋아요 (POST /notes/<id>/like)
@app.route('/notes/<int:note_id>/like', methods=['POST'])
@jwt_required()
def like_note(note_id):
    cursor = mysql.connection.cursor(DictCursor)

    cursor.execute("SELECT * FROM notes WHERE id = %s", (note_id,))
    note = cursor.fetchone()

    if not note:
        cursor.close()
        return jsonify({"error": "소설을 찾을 수 없습니다."}), 404

    cursor.execute("UPDATE notes SET likes = likes + 1 WHERE id = %s", (note_id,))
    mysql.connection.commit()
    cursor.close()

    return jsonify({"message": "좋아요 추가 완료"}), 200

# 8️⃣ ❤️ 좋아요 기준으로 상위 9개 소설 조회 (GET /best9)
@app.route('/best9', methods=['GET'])
def get_best9():
    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM notes ORDER BY likes DESC LIMIT 9")
    best9 = cursor.fetchall()
    cursor.close()
    return jsonify(best9)

# 9️⃣ 👀 특정 소설 조회 (조회수 증가)
@app.route('/notes/<int:note_id>', methods=['GET'])
def get_note(note_id):
    cursor = mysql.connection.cursor(DictCursor)

    try:
        # 조회수 증가
        cursor.execute("UPDATE notes SET views = views + 1 WHERE id = %s", (note_id,))
        mysql.connection.commit()

        # 소설 기본 정보 조회
        cursor.execute("SELECT * FROM notes WHERE id = %s", (note_id,))
        note = cursor.fetchone()
        if not note:
            return jsonify({"error": "소설을 찾을 수 없습니다."}), 404

        # 에피소드 조회
        cursor.execute("SELECT * FROM work_episodes WHERE workId = %s", (note_id,))
        episodes = cursor.fetchall()

        # 각 에피소드에 댓글 추가
        for episode in episodes:
            episode_id = episode["episodeId"] if "episodeId" in episode else episode["id"]
            cursor.execute("""
                SELECT c.id AS commentId, u.nickname AS authorNickname, c.content, c.created_at 
                FROM comments c
                JOIN users u ON c.user_id = u.id
                WHERE c.episode_id = %s
                ORDER BY c.created_at ASC
            """, (episode_id,))
            comments = cursor.fetchall()
            
            episode["comments"] = comments

        note["episodes"] = episodes

        return jsonify(note)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "서버 에러 발생"}), 500

    finally:
        cursor.close()

# 10 내 정보 수정
@app.route('/users/me', methods=['PATCH'])
@jwt_required()
def update_user_info():
    user_id = get_jwt_identity()
    data = request.get_json()
    username = data.get('username')  # 닉네임
    name = data.get('name')          # 실제 이름
    age = data.get('age')            # 나이
    profile_image = data.get('profile_image')

    cursor = mysql.connection.cursor(DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404

    updates = []
    values = []
    if username:
        updates.append("username = %s")
        values.append(username)
    if name:
        updates.append("name = %s")
        values.append(name)
    if age is not None:
        updates.append("age = %s")
        values.append(age)
    if profile_image:
        updates.append("profile_image = %s")
        values.append(profile_image)
    if updates:
        update_query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
        values.append(user_id)
        cursor.execute(update_query, tuple(values))
        mysql.connection.commit()

    cursor.close()
    return jsonify({"message": "회원 정보가 수정되었습니다."}), 200

# 11 👤  마이페이지 조회
@app.route('/users/me', methods=['GET'])
@jwt_required()
def get_my_page():
    user_id = get_jwt_identity()
    cursor = mysql.connection.cursor(DictCursor)

    try:
        # 1. 프로필 정보
        cursor.execute("""
            SELECT username, name, age, profile_image
            FROM users
            WHERE id = %s
        """, (user_id,))
        profile = cursor.fetchone()
        if not profile:
            return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404
        # 2. 최근 본 작품 (최근 5개, 작가 이름 포함)
        cursor.execute("""
            SELECT n.id, n.title, n.image, u.name AS author_name
            FROM views v
            JOIN notes n ON v.note_id = n.id
            JOIN users u ON n.author_id = u.id
            WHERE v.user_id = %s
            ORDER BY v.viewed_at DESC
            LIMIT 5
        """, (user_id,))
        recent_views = cursor.fetchall()

        # 3. 내가 만든 작품
        cursor.execute("""
            SELECT id, title, image, description, likes
            FROM notes
            WHERE author_id = %s
        """, (user_id,))
        my_works = cursor.fetchall()

        # 4. 내가 좋아요한 작품
        cursor.execute("""
            SELECT n.id, n.title, n.image, u.name AS author_name
            FROM likes l
            JOIN notes n ON l.note_id = n.id
            JOIN users u ON n.author_id = u.id
            WHERE l.user_id = %s
        """, (user_id,))
        liked_works = cursor.fetchall()

        return jsonify({
             "profile": profile,
            "recentViews": recent_views,
            "myWorks": my_works,
            "likedWorks": liked_works
        })

    except Exception as e:
        print(f"Error in /users/me: {e}")
        return jsonify({"error": "서버 에러 발생"}), 500
    finally:
        cursor.close()


# 12 작품 에피소드 등록@app.route('/api/episode', methods=['POST'])
@app.route('/api/episode', methods=['POST'])
def add_episode():
    try:
        data = request.get_json()

        if isinstance(data, list):
            data = data[0]

        work_id = data.get('workId')
        content = data.get('content')

        if not work_id or not content:
            return jsonify({'error': 'workId와 content는 필수입니다.'}), 400

        cursor = mysql.connection.cursor()

        # 해당 workId에 대한 에피소드 개수를 가져오는 쿼리 실행
        cursor.execute("SELECT COUNT(*) FROM work_episodes WHERE workId = %s", (work_id,))

        # 쿼리 실행 후 결과 확인
        result = cursor.fetchone()

        # 결과 출력 (디버깅용)
        print(f"Query result: {result}")  # 쿼리 결과 확인

        if result is None or 'COUNT(*)' not in result:
            return jsonify({'error': '쿼리 결과가 없습니다.'}), 500  # 쿼리 결과가 없을 때 처리

        episode_count = result['COUNT(*)'] if result['COUNT(*)'] is not None else 0

        created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # 에피소드 추가
        cursor.execute("""
            INSERT INTO work_episodes (workId, episodeNumber, content, createdAt)
            VALUES (%s, %s, %s, %s)
        """, (work_id, episode_count + 1, content, created_at))

        # 커밋하여 데이터베이스에 저장
        mysql.connection.commit()

        cursor.close()

        # 에피소드 추가 성공
        return jsonify({
            'message': '에피소드 추가 성공',
            'episodeNumber': episode_count + 1,
            'createdAt': created_at
        }), 201

    except Exception as e:
        # 예외 발생 시 에러 로그 출력
        print(f"Error: {e}")  # 에러 로그 출력
        return jsonify({'error': str(e)}), 500

#13 모든 작가의 작품 조회
@app.route('/author/<author_name>/works', methods=['GET'])
def get_works_by_author(author_name):
    cursor = mysql.connection.cursor(DictCursor)
    try:
        # 작가 이름으로 작가 ID 조회
        cursor.execute("SELECT id, name FROM users WHERE name = %s", (author_name,))
        author = cursor.fetchone()
        if not author:
            return jsonify({"error": "해당 작가를 찾을 수 없습니다."}), 404

        # 작가 ID로 해당 작가의 작품 조회
        cursor.execute("""
            SELECT id, title, likes, description, image AS cover_image
            FROM notes
            WHERE author_id = %s
        """, (author['id'],))
        works = cursor.fetchall()

        return jsonify({
            "authorName": author['name'],
            "works": works
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "서버 에러 발생"}), 500
    finally:
        cursor.close()

#18 이미지 업로드
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_image():
    if 'image' not in request.files:
        return jsonify({"error": "이미지 파일이 포함되어야 합니다."}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "파일명이 없습니다."}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_url = request.host_url.rstrip('/') + '/uploads/' + filename
        return jsonify({"url": image_url}), 200

    return jsonify({"error": "허용되지 않는 파일 형식입니다."}), 400
@app.route('/uploads/<filename>')
def serve_uploaded_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 서버 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)