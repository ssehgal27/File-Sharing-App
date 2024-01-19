import hashlib
import pytest
from flask_migrate import migrate
import app
from app import app, db, User, File, encrypt_file
from werkzeug.security import generate_password_hash
from io import BytesIO
import os

@pytest.fixture
def test_client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_database.sqlite'
    app.config['WTF_CSRF_ENABLED'] = False  # Disabling CSRF tokens in the test configuration
    client = app.test_client()

    # Setting up the test database
    with app.app_context():
        db.create_all()

    yield client
    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_user_registration(test_client):
    """
    Test user registration.
    """
    response = test_client.post('/register', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 302  # Redirect to login page

    # Checking if user is added to the database
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user is not None

def test_user_login(test_client):
    """
    Test user login.
    """
    # Creating a test user
    with app.app_context():
        hashed_password = generate_password_hash('testpassword')
        user = User(username='testuser', password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

    response = test_client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 302  # Redirecting to dashboard

def test_file_upload(test_client):
    """
    Test file upload.
    """
    with app.app_context():
        hashed_password = generate_password_hash('testpassword')
        user = User(username='testuser', password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

    # Logging in the test user
    test_client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })

    # Creating a dummy file and send a POST request to upload it
    data = {
        'file': (BytesIO(b"dummy file content"), 'test.txt'),
        'shared_with': ''  # Assuming this is part of your form
    }
    response = test_client.post('/upload', data=data, content_type='multipart/form-data')

    # Checking if the file was uploaded successfully
    assert response.status_code == 302  # Redirecting to dashboard

    # Checking if the file is added to the database
    with app.app_context():
        file = File.query.filter_by(name='test.txt').first()
        assert file is not None

def test_file_download(test_client, caplog):
    """
    Test file download.
    """
    file_id = None  # Initializing variable to store file ID
    with app.app_context():
        # Creating a test user
        hashed_password = generate_password_hash('testpassword')
        user = User(username='testuser', password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Encrypting and adding a test file
        dummy_content = b"dummy file content"
        encrypted_data, iv, key = encrypt_file(dummy_content)
        hash_digest = hashlib.sha256(dummy_content).hexdigest()  # Ensure correct hashing
        file = File(name='test.txt', data=encrypted_data, user_id=user.id, 
                    hash_digest=hash_digest, encryption_key=key.hex(), iv=iv.hex())
        db.session.add(file)
        db.session.commit()

        # Storing the file ID for later use
        file_id = file.id

    assert file_id is not None, "File ID not captured"

    # Logging in the test user
    login_response = test_client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert login_response.status_code == 302, "Login failed"

    # Sending a GET request to download the file
    download_response = test_client.get(f'/download/{file_id}')

    # Checking for padding error in logs
    for record in caplog.records:
        assert 'Padding is incorrect' not in record.message

    # Checking if the file is downloadable
    assert download_response.status_code == 200, f"Expected 200 OK, got {download_response.status_code}"
    assert download_response.data == dummy_content, "Downloaded file content does not match"

def test_file_sharing(test_client):
    """
    Test sharing a file with another user.
    """
    with app.app_context():
        # Creating two test users
        user1 = User(username='testuser1', password_hash=generate_password_hash('testpassword1'))
        user2 = User(username='testuser2', password_hash=generate_password_hash('testpassword2'))
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Encrypting and adding a test file for user1
        encrypted_data, iv, key = encrypt_file(b"file content for sharing")
        file = File(name='sharetest.txt', data=encrypted_data, user_id=user1.id, 
                    hash_digest='dummyhash', shared_users='')  # Ensure shared_users is initialized
        db.session.add(file)
        db.session.commit()

        file_id = file.id
        # Storing encryption key and IV
        os.environ[f'file_key_{file.id}'] = key.hex()
        os.environ[f'file_iv_{file.id}'] = iv.hex()

    # Logging in as user1 and share the file with user2
    test_client.post('/login', data={
        'username': 'testuser1',
        'password': 'testpassword1'
    })
    share_response = test_client.post(f'/share_file/{file_id}', data={'shared_with': 'testuser2'})
    assert share_response.status_code == 302, "Sharing the file failed"

    # Check if the file's shared_users field has been updated
    with app.app_context():
        updated_file = File.query.get(file_id)
        assert updated_file is not None, "File not found"
        assert 'testuser2' in updated_file.shared_users, "File not shared successfully"

