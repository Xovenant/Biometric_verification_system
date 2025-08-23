#!/usr/bin/env python3
"""
Complete Biometric Student Verification System
A comprehensive system for student verification using fingerprint and photo authentication

Author: xovenant
Date: 2025
Version: 1.0.0
"""

import sqlite3
import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import hashlib
import base64
from datetime import datetime
import os
import json
import logging
import configparser
from pathlib import Path
import csv
import threading
import time

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

class Config:
    """Configuration management class"""
    
    def __init__(self):
        self.config_file = 'config.ini'
        self.config = configparser.ConfigParser()
        
        # Default configuration values
        self.defaults = {
            'DATABASE': {
                'path': 'data/student_biometric.db',
                'backup_interval': '24'
            },
            'BIOMETRIC': {
                'fingerprint_threshold': '0.75',
                'face_threshold': '0.80',
                'max_attempts': '3',
                'lockout_duration': '300'
            },
            'CAMERA': {
                'device_index': '0',
                'resolution_width': '640',
                'resolution_height': '480',
                'fps': '30'
            },
            'SECURITY': {
                'encryption_key': 'default_key_change_in_production',
                'session_timeout': '1800',
                'log_level': 'INFO'
            },
            'UI': {
                'theme': 'default',
                'window_width': '1200',
                'window_height': '800',
                'auto_save': 'true'
            }
        }
        
        self.load_config()
        self.setup_properties()
    
    def load_config(self):
        """Load configuration from file or create with defaults"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        for section, options in self.defaults.items():
            self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def setup_properties(self):
        """Setup configuration properties for easy access"""
        # Database settings
        self.database_path = self.get('DATABASE', 'path')
        self.backup_interval = int(self.get('DATABASE', 'backup_interval'))
        
        # Biometric settings
        self.fingerprint_threshold = float(self.get('BIOMETRIC', 'fingerprint_threshold'))
        self.face_threshold = float(self.get('BIOMETRIC', 'face_threshold'))
        self.max_attempts = int(self.get('BIOMETRIC', 'max_attempts'))
        self.lockout_duration = int(self.get('BIOMETRIC', 'lockout_duration'))
        
        # Camera settings
        self.camera_index = int(self.get('CAMERA', 'device_index'))
        self.camera_width = int(self.get('CAMERA', 'resolution_width'))
        self.camera_height = int(self.get('CAMERA', 'resolution_height'))
        self.camera_fps = int(self.get('CAMERA', 'fps'))
        
        # Security settings
        self.encryption_key = self.get('SECURITY', 'encryption_key')
        self.session_timeout = int(self.get('SECURITY', 'session_timeout'))
        self.log_level = self.get('SECURITY', 'log_level')
        
        # UI settings
        self.ui_theme = self.get('UI', 'theme')
        self.window_width = int(self.get('UI', 'window_width'))
        self.window_height = int(self.get('UI', 'window_height'))
        self.auto_save = self.get('UI', 'auto_save').lower() == 'true'
    
    def get(self, section, option):
        """Get configuration value with fallback to defaults"""
        try:
            return self.config.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return self.defaults.get(section, {}).get(option, '')
    
    def set(self, section, option, value):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, option, str(value))
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)

# =============================================================================
# LOGGING SYSTEM
# =============================================================================

def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    Path('logs').mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'logs/biometric_system_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.StreamHandler()
        ]
    )

# =============================================================================
# DATABASE MANAGEMENT
# =============================================================================

class DatabaseManager:
    """Manages all database operations"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.create_tables()
    
    def create_tables(self):
        """Create database tables"""
        cursor = self.connection.cursor()
        
        # Students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                fingerprint_data BLOB,
                photo_data BLOB,
                registration_date TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Verification logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                verification_time TEXT NOT NULL,
                verification_type TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence_score REAL,
                device_info TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_student_id ON students(student_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_student_id ON verification_logs(student_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_time ON verification_logs(verification_time)')
        
        self.connection.commit()
    
    def add_student(self, student_data):
        """Add a new student to the database"""
        cursor = self.connection.cursor()
        
        cursor.execute('''
            INSERT INTO students (student_id, name, email, fingerprint_data, 
                                photo_data, registration_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            student_data['student_id'],
            student_data['name'],
            student_data['email'],
            student_data['fingerprint_data'],
            student_data['photo_data'],
            datetime.now().isoformat(),
            'active'
        ))
        
        self.connection.commit()
        return cursor.lastrowid
    
    def get_student(self, student_id):
        """Get student by ID"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT * FROM students WHERE student_id = ? AND status = 'active'
        ''', (student_id,))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def get_all_students(self):
        """Get all students"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT id, student_id, name, email, status, registration_date
            FROM students ORDER BY registration_date DESC
        ''')
        
        return [dict(row) for row in cursor.fetchall()]
    
    def update_student_status(self, student_id, status):
        """Update student status"""
        cursor = self.connection.cursor()
        cursor.execute('''
            UPDATE students SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE student_id = ?
        ''', (status, student_id))
        
        self.connection.commit()
    
    def log_verification(self, log_data):
        """Log verification attempt"""
        cursor = self.connection.cursor()
        
        cursor.execute('''
            INSERT INTO verification_logs 
            (student_id, verification_time, verification_type, result, 
             confidence_score, device_info)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            log_data['student_id'],
            log_data['verification_time'],
            log_data['verification_type'],
            log_data['result'],
            log_data.get('confidence_score'),
            log_data.get('device_info', '')
        ))
        
        self.connection.commit()
    
    def get_verification_logs(self, limit=1000, student_id=None):
        """Get verification logs"""
        cursor = self.connection.cursor()
        
        if student_id:
            cursor.execute('''
                SELECT * FROM verification_logs 
                WHERE student_id = ?
                ORDER BY verification_time DESC 
                LIMIT ?
            ''', (student_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM verification_logs 
                ORDER BY verification_time DESC 
                LIMIT ?
            ''', (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self):
        """Get system statistics"""
        cursor = self.connection.cursor()
        
        # Total students
        cursor.execute('SELECT COUNT(*) as total FROM students')
        total_students = cursor.fetchone()['total']
        
        # Active students
        cursor.execute('SELECT COUNT(*) as active FROM students WHERE status = "active"')
        active_students = cursor.fetchone()['active']
        
        # Today's verifications
        today = datetime.now().date().isoformat()
        cursor.execute('''
            SELECT COUNT(*) as today_verifications 
            FROM verification_logs 
            WHERE verification_time LIKE ?
        ''', (f"{today}%",))
        today_verifications = cursor.fetchone()['today_verifications']
        
        # Successful verifications today
        cursor.execute('''
            SELECT COUNT(*) as today_successful 
            FROM verification_logs 
            WHERE verification_time LIKE ? AND result = "success"
        ''', (f"{today}%",))
        today_successful = cursor.fetchone()['today_successful']
        
        return {
            'total_students': total_students,
            'active_students': active_students,
            'today_verifications': today_verifications,
            'today_successful': today_successful,
            'success_rate': (today_successful / today_verifications * 100) if today_verifications > 0 else 0
        }
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()

# =============================================================================
# BIOMETRIC PROCESSING
# =============================================================================

class BiometricProcessor:
    """Handles biometric processing operations"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.camera = None
        
    def initialize_camera(self):
        """Initialize camera connection"""
        try:
            self.camera = cv2.VideoCapture(self.config.camera_index)
            
            if self.camera.isOpened():
                self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.config.camera_width)
                self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.config.camera_height)
                self.camera.set(cv2.CAP_PROP_FPS, self.config.camera_fps)
                return True
            else:
                self.camera = None
                return False
                
        except Exception as e:
            self.logger.error(f"Camera initialization error: {e}")
            self.camera = None
            return False
    
    def capture_photo(self):
        """Capture photo from camera"""
        try:
            if self.camera is None or not self.camera.isOpened():
                if not self.initialize_camera():
                    raise Exception("Camera not available")
            
            ret, frame = self.camera.read()
            
            if not ret:
                raise Exception("Failed to capture frame from camera")
            
            # Convert BGR to RGB
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            return rgb_frame
            
        except Exception as e:
            self.logger.error(f"Photo capture failed: {e}")
            return None
    
    def load_photo_from_file(self, file_path):
        """Load photo from file"""
        try:
            image = cv2.imread(file_path)
            if image is None:
                raise Exception(f"Could not load image from {file_path}")
            
            return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
        except Exception as e:
            self.logger.error(f"Failed to load photo from file: {e}")
            return None
    
    def generate_fingerprint_data(self):
        """Generate simulated fingerprint data"""
        timestamp = datetime.now().isoformat()
        
        # Generate simulated minutiae points
        minutiae = []
        minutiae_count = np.random.randint(15, 45)
        
        for i in range(minutiae_count):
            minutiae.append({
                'x': np.random.randint(10, 246),
                'y': np.random.randint(10, 246),
                'angle': np.random.randint(0, 360),
                'type': np.random.choice(['ridge_ending', 'bifurcation']),
                'quality': np.random.uniform(0.7, 0.95)
            })
        
        # Generate template hash
        minutiae_str = json.dumps(minutiae, sort_keys=True)
        template_hash = hashlib.sha256(minutiae_str.encode()).hexdigest()
        
        return {
            'template_hash': template_hash,
            'minutiae': minutiae,
            'quality_score': np.random.uniform(0.65, 0.95),
            'timestamp': timestamp
        }
    
    def match_fingerprints(self, stored_fp, live_fp):
        """Match two fingerprint templates"""
        try:
            stored_minutiae = stored_fp.get('minutiae', [])
            live_minutiae = live_fp.get('minutiae', [])
            
            if not stored_minutiae or not live_minutiae:
                return 0.0
            
            # Simplified matching algorithm
            matches = 0
            total_comparisons = len(stored_minutiae)
            
            for m1 in stored_minutiae:
                best_match = 0.0
                for m2 in live_minutiae:
                    if m1['type'] == m2['type']:
                        pos_dist = np.sqrt((m1['x'] - m2['x'])**2 + (m1['y'] - m2['y'])**2)
                        angle_diff = abs(m1['angle'] - m2['angle'])
                        
                        if pos_dist <= 15 and angle_diff <= 20:
                            match_score = (1.0 - pos_dist/15) * (1.0 - angle_diff/20)
                            best_match = max(best_match, match_score)
                
                if best_match > 0.6:
                    matches += best_match
            
            # Calculate confidence
            confidence = matches / total_comparisons if total_comparisons > 0 else 0.0
            
            # Apply quality factors
            stored_quality = stored_fp.get('quality_score', 0.8)
            live_quality = live_fp.get('quality_score', 0.8)
            quality_factor = min(stored_quality, live_quality)
            
            return min(confidence * quality_factor, 0.99)
            
        except Exception as e:
            self.logger.error(f"Fingerprint matching error: {e}")
            return 0.0
    
    def detect_face(self, image):
        """Detect face in image"""
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
            
            # Use Haar cascade for face detection
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            
            faces = face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(50, 50)
            )
            
            if len(faces) > 0:
                # Return the largest face
                largest_face = max(faces, key=lambda x: x[2] * x[3])
                x, y, w, h = largest_face
                
                # Extract face with padding
                padding = int(min(w, h) * 0.1)
                x1 = max(0, x - padding)
                y1 = max(0, y - padding)
                x2 = min(image.shape[1], x + w + padding)
                y2 = min(image.shape[0], y + h + padding)
                
                face_region = image[y1:y2, x1:x2]
                face_resized = cv2.resize(face_region, (128, 128))
                
                return face_resized
            
            return None
            
        except Exception as e:
            self.logger.error(f"Face detection error: {e}")
            return None
    
    def match_faces(self, stored_photo, live_photo):
        """Match faces in two photos"""
        try:
            stored_face = self.detect_face(stored_photo)
            live_face = self.detect_face(live_photo)
            
            if stored_face is None or live_face is None:
                return 0.0
            
            # Convert to grayscale for comparison
            stored_gray = cv2.cvtColor(stored_face, cv2.COLOR_RGB2GRAY)
            live_gray = cv2.cvtColor(live_face, cv2.COLOR_RGB2GRAY)
            
            # Resize to same size
            live_gray = cv2.resize(live_gray, (stored_gray.shape[1], stored_gray.shape[0]))
            
            # Calculate similarity using template matching
            result = cv2.matchTemplate(stored_gray, live_gray, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, _ = cv2.minMaxLoc(result)
            
            # Calculate histogram similarity
            hist1 = cv2.calcHist([stored_gray], [0], None, [256], [0, 256])
            hist2 = cv2.calcHist([live_gray], [0], None, [256], [0, 256])
            
            cv2.normalize(hist1, hist1, 0, 1, cv2.NORM_MINMAX)
            cv2.normalize(hist2, hist2, 0, 1, cv2.NORM_MINMAX)
            
            hist_correlation = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
            
            # Combine scores
            combined_score = (max_val * 0.6 + hist_correlation * 0.4)
            
            return max(0.0, min(combined_score, 0.99))
            
        except Exception as e:
            self.logger.error(f"Face matching error: {e}")
            return 0.0
    
    def image_to_blob(self, image_array):
        """Convert image array to blob for database storage"""
        _, buffer = cv2.imencode('.jpg', cv2.cvtColor(image_array, cv2.COLOR_RGB2BGR))
        return buffer.tobytes()
    
    def blob_to_image(self, blob_data):
        """Convert blob data back to image array"""
        nparr = np.frombuffer(blob_data, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    
    def fingerprint_to_blob(self, fingerprint_data):
        """Convert fingerprint data to blob for database storage"""
        json_data = json.dumps(fingerprint_data, default=str)
        return json_data.encode('utf-8')
    
    def blob_to_fingerprint(self, blob_data):
        """Convert blob data back to fingerprint data"""
        json_data = blob_data.decode('utf-8')
        return json.loads(json_data)
    
    def validate_photo_quality(self, photo):
        """Validate photo quality"""
        try:
            if photo.shape[0] < 100 or photo.shape[1] < 100:
                return False
            
            # Check if face is detectable
            face = self.detect_face(photo)
            return face is not None
            
        except Exception:
            return False
    
    def validate_fingerprint_quality(self, fp_data):
        """Validate fingerprint quality"""
        try:
            quality_score = fp_data.get('quality_score', 0.0)
            minutiae_count = len(fp_data.get('minutiae', []))
            
            return quality_score >= 0.6 and minutiae_count >= 12
            
        except Exception:
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        if self.camera is not None:
            self.camera.release()
            self.camera = None

# =============================================================================
# GUI APPLICATION
# =============================================================================

class BiometricVerificationSystem:
    """Main application class"""
    
    def __init__(self):
        # Setup logging first
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = Config()
        
        # Initialize components
        self.db_manager = DatabaseManager(self.config.database_path)
        self.biometric_processor = BiometricProcessor(self.config)
        
        # GUI components
        self.root = tk.Tk()
        self.setup_window()
        self.create_interface()
        
        # Current data
        self.current_fingerprint = None
        self.current_photo = None
        self.current_student = None
        
        self.logger.info("Biometric Verification System initialized")
    
    def setup_window(self):
        """Setup main window properties"""
        self.root.title("Biometric Student Verification System")
        self.root.geometry(f"{self.config.window_width}x{self.config.window_height}")
        self.root.configure(bg='#f0f0f0')
        
        # Center window
        self.center_window()
        
        # Configure window close behavior
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width - self.config.window_width) // 2
        y = (screen_height - self.config.window_height) // 2
        
        self.root.geometry(f"{self.config.window_width}x{self.config.window_height}+{x}+{y}")
    
    def create_interface(self):
        """Create the main interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_enrollment_tab()
        self.create_verification_tab()
        self.create_admin_tab()
    
    def create_enrollment_tab(self):
        """Create enrollment tab for registering new students"""
        enrollment_frame = ttk.Frame(self.notebook)
        self.notebook.add(enrollment_frame, text="Student Enrollment")
        
        # Configure grid
        enrollment_frame.grid_rowconfigure(0, weight=1)
        enrollment_frame.grid_columnconfigure(0, weight=1)
        enrollment_frame.grid_columnconfigure(1, weight=1)
        
        # Left panel for student info
        left_panel = ttk.Frame(enrollment_frame)
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(10, 5), pady=10)
        
        # Right panel for preview
        right_panel = ttk.Frame(enrollment_frame)
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)
        
        # Title
        ttk.Label(left_panel, text="Student Enrollment", 
                 font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Student information form
        info_frame = ttk.LabelFrame(left_panel, text="Student Information")
        info_frame.pack(fill='x', pady=(0, 20))
        info_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text="Student ID:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.student_id_entry = ttk.Entry(info_frame, width=30)
        self.student_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(info_frame, text="Full Name:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.student_name_entry = ttk.Entry(info_frame, width=30)
        self.student_name_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(info_frame, text="Email:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.student_email_entry = ttk.Entry(info_frame, width=30)
        self.student_email_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        
        # Biometric capture section
        biometric_frame = ttk.LabelFrame(left_panel, text="Biometric Data Capture")
        biometric_frame.pack(fill='x', pady=(0, 20))
        
        # Fingerprint section
        fp_frame = ttk.Frame(biometric_frame)
        fp_frame.pack(fill='x', pady=5)
        
        ttk.Button(fp_frame, text="📋 Capture Fingerprint", 
                  command=self.capture_fingerprint).pack(side='left', padx=5)
        self.fp_status_label = ttk.Label(fp_frame, text="No fingerprint captured", 
                                        foreground='red')
        self.fp_status_label.pack(side='left', padx=10)
        
        # Photo section
        photo_frame = ttk.Frame(biometric_frame)
        photo_frame.pack(fill='x', pady=5)
        
        ttk.Button(photo_frame, text="📷 Capture Photo", 
                  command=self.capture_photo).pack(side='left', padx=5)
        ttk.Button(photo_frame, text="📁 Upload Photo", 
                  command=self.upload_photo).pack(side='left', padx=5)
        self.photo_status_label = ttk.Label(photo_frame, text="No photo captured", 
                                           foreground='red')
        self.photo_status_label.pack(side='left', padx=10)
        
        # Enrollment buttons
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="✅ Enroll Student", 
                  command=self.enroll_student).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑️ Clear Form", 
                  command=self.clear_enrollment_form).pack(side='left', padx=5)
        
        # Right panel - preview
        ttk.Label(right_panel, text="Biometric Preview", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Photo preview
        self.photo_preview_frame = ttk.LabelFrame(right_panel, text="Student Photo")
        self.photo_preview_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.photo_preview_label = ttk.Label(self.photo_preview_frame, text="No photo")
        self.photo_preview_label.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Fingerprint status
        self.fp_preview_frame = ttk.LabelFrame(right_panel, text="Fingerprint Status")
        self.fp_preview_frame.pack(fill='x')
        
        self.fp_preview_label = ttk.Label(self.fp_preview_frame, text="No fingerprint data")
        self.fp_preview_label.pack(padx=20, pady=20)
    
    def create_verification_tab(self):
        """Create verification tab for exam hall entry"""
        verification_frame = ttk.Frame(self.notebook)
        self.notebook.add(verification_frame, text="Exam Verification")
        
        # Configure grid
        verification_frame.grid_rowconfigure(1, weight=1)
        verification_frame.grid_columnconfigure(0, weight=1)
        
        # Header
        header_frame = ttk.Frame(verification_frame)
        header_frame.grid(row=0, column=0, sticky='ew', padx=20, pady=20)
        header_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(header_frame, text="Test Hall Verification", 
                 font=('Arial', 18, 'bold')).grid(row=0, column=0, columnspan=3, pady=(0, 15))
        
        # Verification method selection
        method_frame = ttk.LabelFrame(header_frame, text="Verification Method")
        method_frame.grid(row=1, column=0, sticky='ew', padx=(0, 10))
        
        self.verification_method = tk.StringVar(value="fingerprint")
        ttk.Radiobutton(method_frame, text="👆 Fingerprint", 
                       variable=self.verification_method, value="fingerprint").pack(side='left', padx=10, pady=5)
        ttk.Radiobutton(method_frame, text="📷 Photo", 
                       variable=self.verification_method, value="photo").pack(side='left', padx=10, pady=5)
        
        # Student ID input
        id_frame = ttk.LabelFrame(header_frame, text="Student Identification")
        id_frame.grid(row=1, column=1, sticky='ew', padx=10)
        id_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(id_frame, text="Student ID:").grid(row=0, column=0, padx=5, pady=5)
        self.verify_student_id_entry = ttk.Entry(id_frame, font=('Arial', 12))
        self.verify_student_id_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        self.verify_student_id_entry.bind('<Return>', lambda e: self.load_student_for_verification())
        
        ttk.Button(id_frame, text="📋 Load Student", 
                  command=self.load_student_for_verification).grid(row=0, column=2, padx=5, pady=5)
        
        # Main verification area
        main_frame = ttk.Frame(verification_frame)
        main_frame.grid(row=1, column=0, sticky='nsew', padx=20, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Left side - capture area
        capture_area = ttk.LabelFrame(main_frame, text="Live Verification")
        capture_area.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        capture_area.grid_rowconfigure(1, weight=1)
        capture_area.grid_columnconfigure(0, weight=1)
        
        self.verify_status_label = ttk.Label(capture_area, text="Ready for verification", 
                                            font=('Arial', 12))
        self.verify_status_label.grid(row=0, column=0, pady=10)
        
        self.verify_display_frame = ttk.Frame(capture_area)
        self.verify_display_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)
        self.verify_display_frame.grid_rowconfigure(0, weight=1)
        self.verify_display_frame.grid_columnconfigure(0, weight=1)
        
        self.verify_display_label = ttk.Label(self.verify_display_frame, 
                                             text="Click 'Start Verification' to begin")
        self.verify_display_label.grid(row=0, column=0, sticky='nsew')
        
        self.start_verify_button = ttk.Button(capture_area, text="🔍 Start Verification", 
                                             command=self.start_verification, state='disabled')
        self.start_verify_button.grid(row=2, column=0, pady=10)
        
        # Right side - stored data
        stored_area = ttk.LabelFrame(main_frame, text="Stored Student Data")
        stored_area.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        stored_area.grid_rowconfigure(1, weight=1)
        stored_area.grid_columnconfigure(0, weight=1)
        
        self.student_info_label = ttk.Label(stored_area, text="No student loaded", 
                                           font=('Arial', 10), anchor='center')
        self.student_info_label.grid(row=0, column=0, pady=10)
        
        self.stored_photo_frame = ttk.Frame(stored_area)
        self.stored_photo_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)
        self.stored_photo_frame.grid_rowconfigure(0, weight=1)
        self.stored_photo_frame.grid_columnconfigure(0, weight=1)
        
        self.stored_photo_label = ttk.Label(self.stored_photo_frame, text="No student loaded")
        self.stored_photo_label.grid(row=0, column=0, sticky='nsew')
        
        # Verification result
        result_frame = ttk.Frame(verification_frame)
        result_frame.grid(row=2, column=0, sticky='ew', padx=20, pady=(10, 20))
        result_frame.grid_columnconfigure(0, weight=1)
        
        result_display_frame = ttk.LabelFrame(result_frame, text="Verification Result")
        result_display_frame.grid(row=0, column=0, sticky='ew', pady=(0, 15))
        result_display_frame.grid_columnconfigure(0, weight=1)
        
        self.result_label = ttk.Label(result_display_frame, text="Ready for verification", 
                                     font=('Arial', 14, 'bold'))
        self.result_label.grid(row=0, column=0, pady=20)
        
        # Action buttons
        action_frame = ttk.Frame(result_frame)
        action_frame.grid(row=1, column=0)
        
        self.grant_access_btn = ttk.Button(action_frame, text="✅ Grant Access", 
                                          command=self.grant_access, state='disabled')
        self.grant_access_btn.pack(side='left', padx=10)
        
        self.deny_access_btn = ttk.Button(action_frame, text="❌ Deny Access", 
                                         command=self.deny_access, state='disabled')
        self.deny_access_btn.pack(side='left', padx=10)
        
        self.reset_verify_btn = ttk.Button(action_frame, text="🔄 Reset", 
                                          command=self.reset_verification)
        self.reset_verify_btn.pack(side='left', padx=10)
    
    def create_admin_tab(self):
        """Create admin panel for system management"""
        admin_frame = ttk.Frame(self.notebook)
        self.notebook.add(admin_frame, text="Admin Panel")
        
        # Configure grid
        admin_frame.grid_rowconfigure(1, weight=1)
        admin_frame.grid_columnconfigure(0, weight=1)
        
        # Header with statistics
        header_frame = ttk.Frame(admin_frame)
        header_frame.grid(row=0, column=0, sticky='ew', padx=20, pady=20)
        header_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(header_frame, text="System Administration", 
                 font=('Arial', 16, 'bold')).grid(row=0, column=0, pady=(0, 15))
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(header_frame, text="System Statistics")
        stats_frame.grid(row=1, column=0, sticky='ew')
        
        # Configure stats grid
        for i in range(5):
            stats_frame.grid_columnconfigure(i, weight=1)
        
        self.total_students_var = tk.StringVar(value="0")
        self.active_students_var = tk.StringVar(value="0")
        self.today_verifications_var = tk.StringVar(value="0")
        self.success_rate_var = tk.StringVar(value="0%")
        self.system_status_var = tk.StringVar(value="Active")
        
        # Create stat displays
        stats = [
            ("Total Students", self.total_students_var),
            ("Active Students", self.active_students_var),
            ("Today's Verifications", self.today_verifications_var),
            ("Success Rate", self.success_rate_var),
            ("System Status", self.system_status_var)
        ]
        
        for i, (label, var) in enumerate(stats):
            stat_frame = ttk.Frame(stats_frame)
            stat_frame.grid(row=0, column=i, padx=10, pady=10)
            
            ttk.Label(stat_frame, text=label, font=('Arial', 9)).pack()
            ttk.Label(stat_frame, textvariable=var, font=('Arial', 12, 'bold')).pack()
        
        # Main content area
        content_frame = ttk.Frame(admin_frame)
        content_frame.grid(row=1, column=0, sticky='nsew', padx=20, pady=(10, 20))
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)
        
        # Create sub-notebook for admin sections
        self.admin_notebook = ttk.Notebook(content_frame)
        self.admin_notebook.grid(row=0, column=0, sticky='nsew')
        
        # Students management tab
        self.create_students_management_tab()
        
        # Logs tab
        self.create_logs_tab()
        
        # Reports tab
        self.create_reports_tab()
    
    def create_students_management_tab(self):
        """Create student management tab"""
        students_frame = ttk.Frame(self.admin_notebook)
        self.admin_notebook.add(students_frame, text="Student Management")
        
        # Configure grid
        students_frame.grid_rowconfigure(1, weight=1)
        students_frame.grid_columnconfigure(0, weight=1)
        
        # Search controls
        search_frame = ttk.Frame(students_frame)
        search_frame.grid(row=0, column=0, sticky='ew', padx=10, pady=10)
        search_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(row=0, column=1, sticky='ew', padx=5)
        search_entry.bind('<KeyRelease>', self.filter_students)
        
        ttk.Button(search_frame, text="🔍 Search", 
                  command=self.filter_students).grid(row=0, column=2, padx=5)
        ttk.Button(search_frame, text="🔄 Refresh", 
                  command=self.refresh_student_list).grid(row=0, column=3, padx=5)
        
        # Student list
        list_frame = ttk.Frame(students_frame)
        list_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=(0, 10))
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview for students
        columns = ('ID', 'Student ID', 'Name', 'Email', 'Status', 'Registered')
        self.students_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        # Configure columns
        for col in columns:
            self.students_tree.heading(col, text=col)
            if col == 'ID':
                self.students_tree.column(col, width=50)
            elif col == 'Student ID':
                self.students_tree.column(col, width=100)
            elif col == 'Name':
                self.students_tree.column(col, width=150)
            elif col == 'Email':
                self.students_tree.column(col, width=200)
            elif col == 'Status':
                self.students_tree.column(col, width=80)
            else:
                self.students_tree.column(col, width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.students_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.students_tree.xview)
        
        self.students_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.students_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        # Management buttons
        button_frame = ttk.Frame(students_frame)
        button_frame.grid(row=2, column=0, sticky='ew', padx=10, pady=10)
        
        ttk.Button(button_frame, text="📝 View Details", 
                  command=self.view_student_details).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔒 Deactivate", 
                  command=self.deactivate_student).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔓 Activate", 
                  command=self.activate_student).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Export Data", 
                  command=self.export_data).pack(side='right', padx=5)
    
    def create_logs_tab(self):
        """Create verification logs tab"""
        logs_frame = ttk.Frame(self.admin_notebook)
        self.admin_notebook.add(logs_frame, text="Verification Logs")
        
        # Configure grid
        logs_frame.grid_rowconfigure(1, weight=1)
        logs_frame.grid_columnconfigure(0, weight=1)
        
        # Filter controls
        filter_frame = ttk.Frame(logs_frame)
        filter_frame.grid(row=0, column=0, sticky='ew', padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Filter by:").pack(side='left', padx=5)
        
        self.log_filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.log_filter_var,
                                   values=["all", "success", "failed", "fingerprint", "photo"],
                                   state="readonly")
        filter_combo.pack(side='left', padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        ttk.Button(filter_frame, text="🔄 Refresh Logs", 
                  command=self.refresh_logs).pack(side='right', padx=5)
        
        # Logs list
        logs_list_frame = ttk.Frame(logs_frame)
        logs_list_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=(0, 10))
        logs_list_frame.grid_rowconfigure(0, weight=1)
        logs_list_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview for logs
        log_columns = ('Time', 'Student ID', 'Type', 'Result', 'Confidence')
        self.logs_tree = ttk.Treeview(logs_list_frame, columns=log_columns, show='headings')
        
        # Configure log columns
        for col in log_columns:
            self.logs_tree.heading(col, text=col)
            if col == 'Time':
                self.logs_tree.column(col, width=130)
            elif col == 'Student ID':
                self.logs_tree.column(col, width=100)
            elif col == 'Type':
                self.logs_tree.column(col, width=100)
            elif col == 'Result':
                self.logs_tree.column(col, width=80)
            else:
                self.logs_tree.column(col, width=80)
        
        # Log scrollbars
        log_v_scrollbar = ttk.Scrollbar(logs_list_frame, orient='vertical', command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=log_v_scrollbar.set)
        
        # Grid layout for logs
        self.logs_tree.grid(row=0, column=0, sticky='nsew')
        log_v_scrollbar.grid(row=0, column=1, sticky='ns')
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports_frame = ttk.Frame(self.admin_notebook)
        self.admin_notebook.add(reports_frame, text="Reports")
        
        # Report controls
        control_frame = ttk.LabelFrame(reports_frame, text="Generate Reports")
        control_frame.pack(fill='x', padx=20, pady=20)
        
        # Report type selection
        self.report_type_var = tk.StringVar(value="daily")
        report_types = [
            ("Daily Summary", "daily"),
            ("Weekly Summary", "weekly"),
            ("Student Activity", "student_activity")
        ]
        
        for text, value in report_types:
            ttk.Radiobutton(control_frame, text=text, variable=self.report_type_var, 
                           value=value).pack(anchor='w', padx=20, pady=2)
        
        ttk.Button(control_frame, text="📋 Generate Report", 
                  command=self.generate_report).pack(pady=15)
        
        # Report preview
        preview_frame = ttk.LabelFrame(reports_frame, text="Report Preview")
        preview_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        text_frame = ttk.Frame(preview_frame)
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.report_text = tk.Text(text_frame, wrap='word', font=('Courier', 10))
        report_scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=self.report_text.yview)
        self.report_text.configure(yscrollcommand=report_scrollbar.set)
        
        self.report_text.pack(side='left', fill='both', expand=True)
        report_scrollbar.pack(side='right', fill='y')
    
    # =============================================================================
    # ENROLLMENT TAB METHODS
    # =============================================================================
    
    def capture_fingerprint(self):
        """Capture fingerprint from scanner"""
        try:
            # Simulate fingerprint capture
            result = messagebox.askyesno("Fingerprint Capture", 
                                       "Place finger on scanner. Simulate capture?")
            if result:
                self.current_fingerprint = self.biometric_processor.generate_fingerprint_data()
                
                if self.biometric_processor.validate_fingerprint_quality(self.current_fingerprint):
                    self.fp_status_label.config(text="✅ Fingerprint captured", foreground='green')
                    quality_score = self.current_fingerprint.get('quality_score', 0.0)
                    minutiae_count = len(self.current_fingerprint.get('minutiae', []))
                    self.fp_preview_label.config(
                        text=f"Quality Score: {quality_score:.2%}\nMinutiae Points: {minutiae_count}\nStatus: Good"
                    )
                else:
                    self.fp_status_label.config(text="❌ Poor quality - try again", foreground='red')
                    messagebox.showwarning("Quality Warning", 
                                         "Fingerprint quality is too low. Please try again.")
                    
        except Exception as e:
            self.logger.error(f"Fingerprint capture error: {e}")
            messagebox.showerror("Error", f"Fingerprint capture failed: {str(e)}")
    
    def capture_photo(self):
        """Capture photo from camera"""
        try:
            photo = self.biometric_processor.capture_photo()
            
            if photo is not None:
                if self.biometric_processor.validate_photo_quality(photo):
                    self.current_photo = photo
                    self.photo_status_label.config(text="✅ Photo captured", foreground='green')
                    self.update_photo_preview(photo)
                else:
                    self.photo_status_label.config(text="❌ Poor quality - try again", foreground='red')
                    messagebox.showwarning("Quality Warning", 
                                         "Photo quality is too low or no face detected. Please try again.")
            else:
                self.photo_status_label.config(text="❌ Capture failed", foreground='red')
                messagebox.showerror("Error", "Failed to capture photo")
                
        except Exception as e:
            self.logger.error(f"Photo capture error: {e}")
            messagebox.showerror("Error", f"Photo capture failed: {str(e)}")
    
    def upload_photo(self):
        """Upload photo from file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select Student Photo",
                filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
            )
            
            if file_path:
                photo = self.biometric_processor.load_photo_from_file(file_path)
                if photo is not None:
                    if self.biometric_processor.validate_photo_quality(photo):
                        self.current_photo = photo
                        self.photo_status_label.config(text="✅ Photo uploaded", foreground='green')
                        self.update_photo_preview(photo)
                    else:
                        self.photo_status_label.config(text="❌ Poor quality photo", foreground='red')
                        messagebox.showwarning("Quality Warning", 
                                             "Photo quality is too low or no face detected.")
                else:
                    messagebox.showerror("Error", "Failed to load image file")
                    
        except Exception as e:
            self.logger.error(f"Photo upload error: {e}")
            messagebox.showerror("Error", f"Photo upload failed: {str(e)}")
    
    def update_photo_preview(self, photo):
        """Update photo preview display"""
        try:
            # Resize photo for preview
            preview_size = 200
            height, width = photo.shape[:2]
            
            if width > height:
                new_width = preview_size
                new_height = int(height * preview_size / width)
            else:
                new_height = preview_size
                new_width = int(width * preview_size / height)
            
            resized = cv2.resize(photo, (new_width, new_height))
            pil_image = Image.fromarray(resized)
            photo_image = ImageTk.PhotoImage(pil_image)
            
            self.photo_preview_label.config(image=photo_image, text="")
            self.photo_preview_label.image = photo_image  # Keep reference
            
        except Exception as e:
            self.logger.error(f"Photo preview update error: {e}")
    
    def enroll_student(self):
        """Enroll student with captured biometric data"""
        try:
            # Validate form data
            student_id = self.student_id_entry.get().strip()
            name = self.student_name_entry.get().strip()
            email = self.student_email_entry.get().strip()
            
            if not student_id or not name:
                messagebox.showerror("Error", "Student ID and Name are required")
                return
            
            if self.current_fingerprint is None:
                messagebox.showerror("Error", "Please capture fingerprint data")
                return
            
            if self.current_photo is None:
                messagebox.showerror("Error", "Please capture or upload a photo")
                return
            
            # Prepare student data
            student_data = {
                'student_id': student_id,
                'name': name,
                'email': email or None,
                'fingerprint_data': self.biometric_processor.fingerprint_to_blob(self.current_fingerprint),
                'photo_data': self.biometric_processor.image_to_blob(self.current_photo)
            }
            
            # Add student to database
            self.db_manager.add_student(student_data)
            
            self.logger.info(f"Student enrolled successfully: {student_id}")
            messagebox.showinfo("Success", f"Student {name} enrolled successfully!")
            
            # Clear form
            self.clear_enrollment_form()
            
            # Refresh admin data
            self.refresh_student_list()
            self.update_statistics()
            
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Student ID already exists")
        except Exception as e:
            self.logger.error(f"Student enrollment error: {e}")
            messagebox.showerror("Error", f"Failed to enroll student: {str(e)}")
    
    def clear_enrollment_form(self):
        """Clear enrollment form"""
        self.student_id_entry.delete(0, tk.END)
        self.student_name_entry.delete(0, tk.END)
        self.student_email_entry.delete(0, tk.END)
        
        self.current_fingerprint = None
        self.current_photo = None
        
        self.fp_status_label.config(text="No fingerprint captured", foreground='red')
        self.photo_status_label.config(text="No photo captured", foreground='red')
        self.photo_preview_label.config(image="", text="No photo")
        self.fp_preview_label.config(text="No fingerprint data")
    
    # =============================================================================
    # VERIFICATION TAB METHODS
    # =============================================================================
    
    def load_student_for_verification(self):
        """Load student data for verification"""
        try:
            student_id = self.verify_student_id_entry.get().strip()
            if not student_id:
                messagebox.showerror("Error", "Please enter Student ID")
                return
            
            # Reset previous state
            self.reset_verification()
            
            # Load student from database
            student_data = self.db_manager.get_student(student_id)
            
            if not student_data:
                messagebox.showerror("Error", "Student not found")
                return
            
            # Store current student
            self.current_student = student_data
            
            # Update display
            info_text = f"Name: {student_data['name']}\n"
            info_text += f"ID: {student_data['student_id']}\n"
            info_text += f"Email: {student_data['email'] or 'N/A'}\n"
            info_text += f"Status: {student_data['status'].title()}"
            self.student_info_label.config(text=info_text)
            
            # Display stored photo
            if student_data['photo_data']:
                stored_photo = self.biometric_processor.blob_to_image(student_data['photo_data'])
                self.update_stored_photo_display(stored_photo)
            
            # Enable verification
            self.start_verify_button.config(state='normal')
            
            self.logger.info(f"Student loaded for verification: {student_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to load student: {e}")
            messagebox.showerror("Error", f"Failed to load student: {str(e)}")
    
    def update_stored_photo_display(self, photo_array):
        """Update stored photo display"""
        try:
            # Resize for display
            display_size = 150
            height, width = photo_array.shape[:2]
            
            if width > height:
                new_width = display_size
                new_height = int(height * display_size / width)
            else:
                new_height = display_size
                new_width = int(width * display_size / height)
            
            resized = cv2.resize(photo_array, (new_width, new_height))
            pil_image = Image.fromarray(resized)
            photo_image = ImageTk.PhotoImage(pil_image)
            
            self.stored_photo_label.config(image=photo_image, text="")
            self.stored_photo_label.image = photo_image  # Keep reference
            
        except Exception as e:
            self.logger.error(f"Failed to update stored photo display: {e}")
    
    def start_verification(self):
        """Start the verification process"""
        try:
            if not self.current_student:
                messagebox.showerror("Error", "Please load a student first")
                return
            
            method = self.verification_method.get()
            
            if method == "fingerprint":
                self.verify_fingerprint()
            else:
                self.verify_photo()
                
        except Exception as e:
            self.logger.error(f"Verification start error: {e}")
            messagebox.showerror("Error", f"Failed to start verification: {str(e)}")
    
    def verify_fingerprint(self):
        """Perform fingerprint verification"""
        try:
            self.verify_status_label.config(text="Place finger on scanner...")
            self.root.update()
            
            # Simulate user confirmation
            if not messagebox.askyesno("Fingerprint Verification", 
                                     "Place finger on scanner and click 'Yes' to proceed"):
                self.verify_status_label.config(text="Verification cancelled")
                return
            
            # Capture live fingerprint
            live_fp = self.biometric_processor.generate_fingerprint_data()
            
            if not live_fp:
                raise Exception("Failed to capture fingerprint")
            
            # Perform verification
            stored_fp_data = self.current_student['fingerprint_data']
            if not stored_fp_data:
                raise Exception("No stored fingerprint data for student")
            
            stored_fp = self.biometric_processor.blob_to_fingerprint(stored_fp_data)
            confidence = self.biometric_processor.match_fingerprints(stored_fp, live_fp)
            
            is_match = confidence >= self.config.fingerprint_threshold
            
            # Log verification attempt
            self.log_verification_attempt("fingerprint", is_match, confidence)
            
            # Display result
            self.display_verification_result(is_match, confidence, "fingerprint")
            
        except Exception as e:
            self.logger.error(f"Fingerprint verification error: {e}")
            self.verify_status_label.config(text="Verification failed")
            messagebox.showerror("Error", f"Fingerprint verification failed: {str(e)}")
    
    def verify_photo(self):
        """Perform photo verification"""
        try:
            self.verify_status_label.config(text="Capturing photo...")
            self.root.update()
            
            # Capture live photo
            live_photo = self.biometric_processor.capture_photo()
            
            if live_photo is None:
                raise Exception("Failed to capture photo")
            
            # Display captured photo
            self.display_live_photo(live_photo)
            
            # Perform verification
            stored_photo_data = self.current_student['photo_data']
            if not stored_photo_data:
                raise Exception("No stored photo data for student")
            
            stored_photo = self.biometric_processor.blob_to_image(stored_photo_data)
            confidence = self.biometric_processor.match_faces(stored_photo, live_photo)
            
            is_match = confidence >= self.config.face_threshold
            
            # Log verification attempt
            self.log_verification_attempt("photo", is_match, confidence)
            
            # Display result
            self.display_verification_result(is_match, confidence, "photo")
            
        except Exception as e:
            self.logger.error(f"Photo verification error: {e}")
            self.verify_status_label.config(text="Verification failed")
            messagebox.showerror("Error", f"Photo verification failed: {str(e)}")
    
    def display_live_photo(self, photo_array):
        """Display captured live photo"""
        try:
            # Resize for display
            display_size = 200
            height, width = photo_array.shape[:2]
            
            if width > height:
                new_width = display_size
                new_height = int(height * display_size / width)
            else:
                new_height = display_size
                new_width = int(width * display_size / height)
            
            resized = cv2.resize(photo_array, (new_width, new_height))
            pil_image = Image.fromarray(resized)
            photo_image = ImageTk.PhotoImage(pil_image)
            
            self.verify_display_label.config(image=photo_image, text="")
            self.verify_display_label.image = photo_image  # Keep reference
            
        except Exception as e:
            self.logger.error(f"Failed to display live photo: {e}")
    
    def display_verification_result(self, is_match, confidence, method):
        """Display verification result"""
        try:
            if is_match:
                result_text = f"✅ VERIFICATION SUCCESSFUL\n"
                result_text += f"Method: {method.title()}\n"
                result_text += f"Confidence: {confidence:.1%}"
                
                self.result_label.config(text=result_text, foreground='green')
                
                # Enable access control buttons
                self.grant_access_btn.config(state='normal')
                self.deny_access_btn.config(state='normal')
                
                self.verify_status_label.config(text="Verification successful")
                
            else:
                threshold = (self.config.fingerprint_threshold if method == "fingerprint" 
                           else self.config.face_threshold)
                
                result_text = f"❌ VERIFICATION FAILED\n"
                result_text += f"Method: {method.title()}\n"
                result_text += f"Confidence: {confidence:.1%}\n"
                result_text += f"(Below threshold: {threshold:.1%})"
                
                self.result_label.config(text=result_text, foreground='red')
                
                # Enable deny button only
                self.grant_access_btn.config(state='disabled')
                self.deny_access_btn.config(state='normal')
                
                self.verify_status_label.config(text="Verification failed")
                
        except Exception as e:
            self.logger.error(f"Failed to display verification result: {e}")
    
    def log_verification_attempt(self, method, success, confidence):
        """Log verification attempt"""
        try:
            log_data = {
                'student_id': self.current_student['student_id'],
                'verification_time': datetime.now().isoformat(),
                'verification_type': method,
                'result': 'success' if success else 'failed',
                'confidence_score': confidence,
                'device_info': f"camera_status:connected,scanner_status:simulated"
            }
            
            self.db_manager.log_verification(log_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log verification attempt: {e}")
    
    def grant_access(self):
        """Grant access to examination hall"""
        try:
            student_id = self.current_student['student_id']
            student_name = self.current_student['name']
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Log access decision
            self.log_access_decision("granted")
            
            messagebox.showinfo("Access Granted", 
                               f"Access GRANTED to examination hall\n\n"
                               f"Student: {student_name}\n"
                               f"ID: {student_id}\n"
                               f"Time: {timestamp}")
            
            self.logger.info(f"Access granted to student: {student_id}")
            
            # Reset for next verification
            self.reset_verification()
            
        except Exception as e:
            self.logger.error(f"Grant access error: {e}")
            messagebox.showerror("Error", f"Failed to grant access: {str(e)}")
    
    def deny_access(self):
        """Deny access to examination hall"""
        try:
            student_id = self.current_student['student_id']
            student_name = self.current_student['name']
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Log access decision
            self.log_access_decision("denied")
            
            messagebox.showwarning("Access Denied", 
                                  f"Access DENIED to examination hall\n\n"
                                  f"Student: {student_name}\n"
                                  f"ID: {student_id}\n"
                                  f"Time: {timestamp}\n\n"
                                  f"Reason: Biometric verification failed")
            
            self.logger.warning(f"Access denied to student: {student_id}")
            
            # Reset for next verification
            self.reset_verification()
            
        except Exception as e:
            self.logger.error(f"Deny access error: {e}")
            messagebox.showerror("Error", f"Failed to deny access: {str(e)}")
    
    def log_access_decision(self, decision):
        """Log access grant/deny decision"""
        try:
            log_data = {
                'student_id': self.current_student['student_id'],
                'verification_time': datetime.now().isoformat(),
                'verification_type': 'access_decision',
                'result': decision,
                'confidence_score': 1.0,
                'device_info': f"operator_decision_{decision}"
            }
            
            self.db_manager.log_verification(log_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log access decision: {e}")
    
    def reset_verification(self):
        """Reset verification interface"""
        try:
            # Clear current student
            self.current_student = None
            
            # Reset displays
            self.student_info_label.config(text="No student loaded")
            self.stored_photo_label.config(image="", text="No student loaded")
            
            self.verify_display_label.config(image="", text="Click 'Start Verification' to begin")
            self.verify_status_label.config(text="Ready for verification")
            
            self.result_label.config(text="Ready for verification", foreground='black')
            
            # Reset buttons
            self.start_verify_button.config(state='disabled')
            self.grant_access_btn.config(state='disabled')
            self.deny_access_btn.config(state='disabled')
            
            # Clear student ID entry
            self.verify_student_id_entry.delete(0, tk.END)
            
        except Exception as e:
            self.logger.error(f"Reset verification error: {e}")
    
    # =============================================================================
    # ADMIN TAB METHODS
    # =============================================================================
    
    def update_statistics(self):
        """Update system statistics"""
        try:
            stats = self.db_manager.get_statistics()
            
            self.total_students_var.set(str(stats['total_students']))
            self.active_students_var.set(str(stats['active_students']))
            self.today_verifications_var.set(str(stats['today_verifications']))
            self.success_rate_var.set(f"{stats['success_rate']:.1f}%")
            
            # System status based on recent activity
            if stats['today_verifications'] > 0:
                self.system_status_var.set("Active")
            else:
                self.system_status_var.set("Idle")
                
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def refresh_student_list(self):
        """Refresh student list"""
        try:
            # Clear existing items
            for item in self.students_tree.get_children():
                self.students_tree.delete(item)
            
            # Get students from database
            students = self.db_manager.get_all_students()
            
            # Filter students based on search
            search_term = self.search_var.get().lower()
            if search_term:
                students = [s for s in students if 
                          search_term in s['student_id'].lower() or 
                          search_term in s['name'].lower() or 
                          search_term in (s['email'] or '').lower()]
            
            # Populate tree
            for student in students:
                reg_date = student['registration_date'][:10] if student['registration_date'] else "N/A"
                
                self.students_tree.insert('', 'end', values=(
                    student['id'],
                    student['student_id'],
                    student['name'],
                    student['email'] or "N/A",
                    student['status'].title(),
                    reg_date
                ))
                
        except Exception as e:
            self.logger.error(f"Failed to refresh student list: {e}")
            messagebox.showerror("Error", f"Failed to refresh student list: {str(e)}")
    
    def filter_students(self, event=None):
        """Filter student list based on search"""
        self.refresh_student_list()
    
    def view_student_details(self):
        """View detailed student information"""
        selection = self.students_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a student to view details")
            return
        
        item = self.students_tree.item(selection[0])
        student_data = item['values']
        student_id = student_data[1]
        
        try:
            student = self.db_manager.get_student(student_id)
            if student:
                details = f"""Student Details:
                
ID: {student['student_id']}
Name: {student['name']}
Email: {student['email'] or 'N/A'}
Status: {student['status'].title()}
Registered: {student['registration_date'][:19] if student['registration_date'] else 'N/A'}

Biometric Data:
Fingerprint: {'Available' if student['fingerprint_data'] else 'Not Available'}
Photo: {'Available' if student['photo_data'] else 'Not Available'}"""
                
                messagebox.showinfo("Student Details", details)
            else:
                messagebox.showerror("Error", "Student not found")
                
        except Exception as e:
            self.logger.error(f"Failed to view student details: {e}")
            messagebox.showerror("Error", f"Failed to load student details: {str(e)}")
    
    def deactivate_student(self):
        """Deactivate selected student"""
        selection = self.students_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a student to deactivate")
            return
        
        item = self.students_tree.item(selection[0])
        student_data = item['values']
        student_id = student_data[1]
        
        try:
            self.db_manager.update_student_status(student_id, 'inactive')
            messagebox.showinfo("Success", f"Student {student_id} deactivated successfully")
            self.refresh_student_list()
            self.update_statistics()
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate student: {e}")
            messagebox.showerror("Error", f"Failed to deactivate student: {str(e)}")
    
    def activate_student(self):
        """Activate selected student"""
        selection = self.students_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a student to activate")
            return
        
        item = self.students_tree.item(selection[0])
        student_data = item['values']
        student_id = student_data[1]
        
        try:
            self.db_manager.update_student_status(student_id, 'active')
            messagebox.showinfo("Success", f"Student {student_id} activated successfully")
            self.refresh_student_list()
            self.update_statistics()
            
        except Exception as e:
            self.logger.error(f"Failed to activate student: {e}")
            messagebox.showerror("Error", f"Failed to activate student: {str(e)}")
    
    def export_data(self):
        """Export system data"""
        try:
            export_dir = filedialog.askdirectory(title="Select Export Directory")
            if not export_dir:
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Export students
            students = self.db_manager.get_all_students()
            students_file = os.path.join(export_dir, f"students_export_{timestamp}.csv")
            
            with open(students_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Student ID', 'Name', 'Email', 'Status', 'Registration Date'])
                for student in students:
                    writer.writerow([
                        student['student_id'],
                        student['name'],
                        student['email'] or '',
                        student['status'],
                        student['registration_date']
                    ])
            
            # Export logs
            logs = self.db_manager.get_verification_logs(limit=10000)
            logs_file = os.path.join(export_dir, f"verification_logs_{timestamp}.csv")
            
            with open(logs_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Time', 'Student ID', 'Type', 'Result', 'Confidence'])
                for log in logs:
                    writer.writerow([
                        log['verification_time'],
                        log['student_id'],
                        log['verification_type'],
                        log['result'],
                        log['confidence_score']
                    ])
            
            messagebox.showinfo("Export Complete", 
                               f"Data exported successfully to:\n{export_dir}")
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def refresh_logs(self):
        """Refresh verification logs"""
        try:
            # Clear existing items
            for item in self.logs_tree.get_children():
                self.logs_tree.delete(item)
            
            # Get logs from database
            logs = self.db_manager.get_verification_logs(limit=1000)
            
            # Filter logs
            filter_type = self.log_filter_var.get()
            if filter_type != "all":
                logs = [log for log in logs if 
                       filter_type in log['result'] or 
                       filter_type in log['verification_type']]
            
            # Populate logs tree
            for log in logs:
                time_str = log['verification_time'][:19].replace('T', ' ')
                confidence_str = f"{log['confidence_score']:.1%}" if log['confidence_score'] else "N/A"
                
                self.logs_tree.insert('', 'end', values=(
                    time_str,
                    log['student_id'],
                    log['verification_type'].title(),
                    log['result'].title(),
                    confidence_str
                ))
                
        except Exception as e:
            self.logger.error(f"Failed to refresh logs: {e}")
            messagebox.showerror("Error", f"Failed to refresh logs: {str(e)}")
    
    def filter_logs(self, event=None):
        """Filter logs based on selection"""
        self.refresh_logs()
    
    def generate_report(self):
        """Generate selected report"""
        try:
            report_type = self.report_type_var.get()
            
            # Clear previous report
            self.report_text.delete(1.0, tk.END)
            
            if report_type == "daily":
                report = self.generate_daily_report()
            elif report_type == "weekly":
                report = self.generate_weekly_report()
            elif report_type == "student_activity":
                report = self.generate_student_activity_report()
            else:
                report = "Report generation not implemented for this type"
            
            self.report_text.insert(tk.END, report)
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            messagebox.showerror("Error", f"Report generation failed: {str(e)}")
    
    def generate_daily_report(self):
        """Generate daily summary report"""
        try:
            today = datetime.now().date()
            stats = self.db_manager.get_statistics()
            
            report = f"""DAILY SUMMARY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Date: {today}

=== SYSTEM OVERVIEW ===
Total Students: {stats['total_students']}
Active Students: {stats['active_students']}
Today's Verifications: {stats['today_verifications']}
Success Rate: {stats['success_rate']:.1f}%

=== VERIFICATION BREAKDOWN ===
"""
            
            # Get today's logs
            today_str = today.isoformat()
            logs = self.db_manager.get_verification_logs(limit=1000)
            today_logs = [log for log in logs if log['verification_time'].startswith(today_str)]
            
            # Count by type and result
            fingerprint_success = len([log for log in today_logs if 
                                     log['verification_type'] == 'fingerprint' and log['result'] == 'success'])
            fingerprint_failed = len([log for log in today_logs if 
                                    log['verification_type'] == 'fingerprint' and log['result'] == 'failed'])
            photo_success = len([log for log in today_logs if 
                               log['verification_type'] == 'photo' and log['result'] == 'success'])
            photo_failed = len([log for log in today_logs if 
                              log['verification_type'] == 'photo' and log['result'] == 'failed'])
            
            report += f"""Fingerprint Verifications:
  Successful: {fingerprint_success}
  Failed: {fingerprint_failed}

Photo Verifications:
  Successful: {photo_success}
  Failed: {photo_failed}

=== ACCESS DECISIONS ===
"""
            
            access_granted = len([log for log in today_logs if 'granted' in log['result']])
            access_denied = len([log for log in today_logs if 'denied' in log['result']])
            
            report += f"""Access Granted: {access_granted}
Access Denied: {access_denied}

=== RECENT ACTIVITY ===
"""
            
            # Show recent activity
            recent_logs = today_logs[:10]  # Last 10 activities
            for log in recent_logs:
                time_str = log['verification_time'][11:19]  # Just time part
                confidence = f" ({log['confidence_score']:.1%})" if log['confidence_score'] else ""
                report += f"{time_str} - {log['student_id']} - {log['verification_type']} - {log['result']}{confidence}\n"
            
            return report
            
        except Exception as e:
            return f"Error generating daily report: {str(e)}"
    
    def generate_weekly_report(self):
        """Generate weekly summary report"""
        return "Weekly Report\n\nWeekly report generation would show 7-day trends and patterns."
    
    def generate_student_activity_report(self):
        """Generate student activity report"""
        try:
            students = self.db_manager.get_all_students()
            logs = self.db_manager.get_verification_logs(limit=1000)
            
            report = f"""STUDENT ACTIVITY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== MOST ACTIVE STUDENTS ===
"""
            
            # Count verifications per student
            student_activity = {}
            for log in logs:
                student_id = log['student_id']
                if student_id not in student_activity:
                    student_activity[student_id] = 0
                student_activity[student_id] += 1
            
            # Sort by activity
            sorted_activity = sorted(student_activity.items(), key=lambda x: x[1], reverse=True)
            
            for i, (student_id, count) in enumerate(sorted_activity[:10]):
                # Find student name
                student_name = "Unknown"
                for student in students:
                    if student['student_id'] == student_id:
                        student_name = student['name']
                        break
                
                report += f"{i+1}. {student_name} ({student_id}) - {count} verifications\n"
            
            return report
            
        except Exception as e:
            return f"Error generating student activity report: {str(e)}"
    
    # =============================================================================
    # APPLICATION LIFECYCLE METHODS
    # =============================================================================
    
    def on_window_close(self):
        """Handle window close event"""
        try:
            # Confirm before closing
            if messagebox.askyesno("Exit", "Are you sure you want to exit the application?"):
                self.cleanup()
                self.root.destroy()
                
        except Exception as e:
            self.logger.error(f"Error during window close: {e}")
            self.root.destroy()
    
    def cleanup(self):
        """Cleanup resources on application exit"""
        try:
            self.logger.info("Cleaning up application resources...")
            
            # Cleanup biometric processor
            self.biometric_processor.cleanup()
            
            # Close database connection
            self.db_manager.close()
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def run(self):
        """Start the application"""
        try:
            self.logger.info("Starting GUI main loop...")
            
            # Initialize data
            self.update_statistics()
            self.refresh_student_list()
            self.refresh_logs()
            
            # Start main loop
            self.root.mainloop()
            
        except Exception as e:
            self.logger.error(f"Application runtime error: {e}")
            raise


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        'data',
        'logs'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

def main():
    """Main application entry point"""
    try:
        print("=== Biometric Student Verification System ===")
        print("Initializing system...")
        
        # Create necessary directories
        create_directories()
        
        # Initialize and run the application
        app = BiometricVerificationSystem()
        app.run()
        
    except Exception as e:
        print(f"Failed to start application: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

            #!/usr/bin/env python3
"""
Complete Biometric Student Verification System
A comprehensive system for student verification using fingerprint and photo authentication

Author: System Developer
Date: 2025
Version: 1.0.0
"""

import sqlite3
import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import hashlib
import base64
from datetime import datetime
import os
import json
import logging
import configparser
from pathlib import Path
import csv
import threading
import time

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

class Config:
    """Configuration management class"""
    
    def __init__(self):
        self.config_file = 'config.ini'
        self.config = configparser.ConfigParser()
        
        # Default configuration values
        self.defaults = {
            'DATABASE': {
                'path': 'data/student_biometric.db',
                'backup_interval': '24'
            },
            'BIOMETRIC': {
                'fingerprint_threshold': '0.75',
                'face_threshold': '0.80',
                'max_attempts': '3',
                'lockout_duration': '300'
            },
            'CAMERA': {
                'device_index': '0',
                'resolution_width': '640',
                'resolution_height': '480',
                'fps': '30'
            },
            'SECURITY': {
                'encryption_key': 'default_key_change_in_production',
                'session_timeout': '1800',
                'log_level': 'INFO'
            },
            'UI': {
                'theme': 'default',
                'window_width': '1200',
                'window_height': '800',
                'auto_save': 'true'
            }
        }
        
        self.load_config()
        self.setup_properties()
    
    def load_config(self):
        """Load configuration from file or create with defaults"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        for section, options in self.defaults.items():
            self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def setup_properties(self):
        """Setup configuration properties for easy access"""
        # Database settings
        self.database_path = self.get('DATABASE', 'path')
        self.backup_interval = int(self.get('DATABASE', 'backup_interval'))
        
        # Biometric settings
        self.fingerprint_threshold = float(self.get('BIOMETRIC', 'fingerprint_threshold'))
        self.face_threshold = float(self.get('BIOMETRIC', 'face_threshold'))
        self.max_attempts = int(self.get('BIOMETRIC', 'max_attempts'))
        self.lockout_duration = int(self.get('BIOMETRIC', 'lockout_duration'))
        
        # Camera settings
        self.camera_index = int(self.get('CAMERA', 'device_index'))
        self.camera_width = int(self.get('CAMERA', 'resolution_width'))
        self.camera_height = int(self.get('CAMERA', 'resolution_height'))
        self.camera_fps = int(self.get('CAMERA', 'fps'))
        
        # Security settings
        self.encryption_key = self.get('SECURITY', 'encryption_key')
        self.session_timeout = int(self.get('SECURITY', 'session_timeout'))
        self.log_level = self.get('SECURITY', 'log_level')
        
        # UI settings
        self.ui_theme = self.get('UI', 'theme')
        self.window_width = int(self.get('UI', 'window_width'))
        self.window_height = int(self.get('UI', 'window_height'))
        self.auto_save = self.get('UI', 'auto_save').lower() == 'true'
    
    def get(self, section, option):
        """Get configuration value with fallback to defaults"""
        try:
            return self.config.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return self.defaults.get(section, {}).get(option, '')
    
    def set(self, section, option, value):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, option, str(value))
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)

# =============================================================================
# LOGGING SYSTEM
# =============================================================================

def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    Path('logs').mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'logs/biometric_system_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.StreamHandler()
        ]
    )

# =============================================================================
# DATABASE MANAGEMENT
# =============================================================================

class DatabaseManager:
    """Manages all database operations"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.create_tables()
    
    def create_tables(self):
        """Create database tables"""
        cursor = self.connection.cursor()
        
        # Students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                fingerprint_data BLOB,
                photo_data BLOB,
                registration_date TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Verification logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                verification_time TEXT NOT NULL,
                verification_type TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence_score REAL,
                device_info TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_student_id ON students(student_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_student_id ON verification_logs(student_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_time ON verification_logs(verification_time)')
        
        self.connection.commit()
    
    def add_student(self, student_data):
        """Add a new student to the database"""
        cursor = self.connection.cursor()
        
        cursor.execute('''
            INSERT INTO students (student_id, name, email, fingerprint_data, 
                                photo_data, registration_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            student_data['student_id'],
            student_data['name'],
            student_data['email'],
            student_data['fingerprint_data'],
            student_data['photo_data'],
            datetime.now().isoformat(),
            'active'
        ))
        
        self.connection.commit()
        return cursor.lastrowid
    
    def get_student(self, student_id):
        """Get student by ID"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT * FROM students WHERE student_id = ? AND status = 'active'
        ''', (student_id,))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def get_all_students(self):
        """Get all students"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT id, student_id, name, email, status, registration_date
            FROM students ORDER BY registration_date DESC
        ''')
        
        return [dict(row) for row in cursor.fetchall()]
    
    def update_student_status(self, student_id, status):
        """Update student status"""
        cursor = self.connection.cursor()
        cursor.execute('''
            UPDATE students SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE student_id = ?
        ''', (status, student_id))
        
        self.connection.commit()
    
    def log_verification(self, log_data):
        """Log verification attempt"""
        cursor = self.connection.cursor()
        
        cursor.execute('''
            INSERT INTO verification_logs 
            (student_id, verification_time, verification_type, result, 
             confidence_score, device_info)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            log_data['student_id'],
            log_data['verification_time'],
            log_data['verification_type'],
            log_data['result'],
            log_data.get('confidence_score'),
            log_data.get('device_info', '')
        ))
        
        self.connection.commit()
    
    def get_verification_logs(self, limit=1000, student_id=None):
        """Get verification logs"""
        cursor = self.connection.cursor()
        
        if student_id:
            cursor.execute('''
                SELECT * FROM verification_logs 
                WHERE student_id = ?
                ORDER BY verification_time DESC 
                LIMIT ?
            ''', (student_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM verification_logs 
                ORDER BY verification_time DESC 
                LIMIT ?
            ''', (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self):
        """Get system statistics"""
        cursor = self.connection.cursor()
        
        # Total students
        cursor.execute('SELECT COUNT(*) as total FROM students')
        total_students = cursor.fetchone()['total']
        
        # Active students
        cursor.execute('SELECT COUNT(*) as active FROM students WHERE status = "active"')
        active_students = cursor.fetchone()['active']
        
        # Today's verifications
        today = datetime.now().date().isoformat()
        cursor.execute('''
            SELECT COUNT(*) as today_verifications 
            FROM verification_logs 
            WHERE verification_time LIKE ?
        ''', (f"{today}%",))
        today_verifications = cursor.fetchone()['today_verifications']
        
        # Successful verifications today
        cursor.execute('''
            SELECT COUNT(*) as today_successful 
            FROM verification_logs 
            WHERE verification_time LIKE ? AND result = "success"
        ''', (f"{today}%",))
        today_successful = cursor.fetchone()['today_successful']
        
        return {
            'total_students': total_students,
            'active_students': active_students,
            'today_verifications': today_verifications,
            'today_successful': today_successful,
            'success_rate': (today_successful / today_verifications * 100) if today_verifications > 0 else 0
        }
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()

# =============================================================================
# BIOMETRIC PROCESSING
# =============================================================================

class BiometricProcessor:
    """Handles biometric processing operations"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.camera = None
        
    def initialize_camera(self):
        """Initialize camera connection"""
        try:
            self.camera = cv2.VideoCapture(self.config.camera_index)
            
            if self.camera.isOpened():
                self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.config.camera_width)
                self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.config.camera_height)
                self.camera.set(cv2.CAP_PROP_FPS, self.config.camera_fps)
                return True
            else:
                self.camera = None
                return False
                
        except Exception as e:
            self.logger.error(f"Camera initialization error: {e}")
            self.camera = None
            return False
    
    def capture_photo(self):
        """Capture photo from camera"""
        try:
            if self.camera is None or not self.camera.isOpened():
                if not self.initialize_camera():
                    raise Exception("Camera not available")
            
            ret, frame = self.camera.read()
            
            if not ret:
                raise Exception("Failed to capture frame from camera")
            
            # Convert BGR to RGB
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            return rgb_frame
            
        except Exception as e:
            self.logger.error(f"Photo capture failed: {e}")
            return None
    
    def load_photo_from_file(self, file_path):
        """Load photo from file"""
        try:
            image = cv2.imread(file_path)
            if image is None:
                raise Exception(f"Could not load image from {file_path}")
            
            return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
        except Exception as e:
            self.logger.error(f"Failed to load photo from file: {e}")
            return None
    
    def generate_fingerprint_data(self):
        """Generate simulated fingerprint data"""
        timestamp = datetime.now().isoformat()
        
        # Generate simulated minutiae points
        minutiae = []
        minutiae_count = np.random.randint(15, 45)
        
        for i in range(minutiae_count):
            minutiae.append({
                'x': np.random.randint(10, 246),
                'y': np.random.randint(10, 246),
                'angle': np.random.randint(0, 360),
                'type': np.random.choice(['ridge_ending', 'bifurcation']),
                'quality': np.random.uniform(0.7, 0.95)
            })
        
        # Generate template hash
        minutiae_str = json.dumps(minutiae, sort_keys=True)
        template_hash = hashlib.sha256(minutiae_str.encode()).hexdigest()
        
        return {
            'template_hash': template_hash,
            'minutiae': minutiae,
            'quality_score': np.random.uniform(0.65, 0.95),
            'timestamp': timestamp
        }
    
    def match_fingerprints(self, stored_fp, live_fp):
        """Match two fingerprint templates"""
        try:
            stored_minutiae = stored_fp.get('minutiae', [])
            live_minutiae = live_fp.get('minutiae', [])
            
            if not stored_minutiae or not live_minutiae:
                return 0.0
            
            # Simplified matching algorithm
            matches = 0
            total_comparisons = len(stored_minutiae)
            
            for m1 in stored_minutiae:
                best_match = 0.0
                for m2 in live_minutiae:
                    if m1['type'] == m2['type']:
                        pos_dist = np.sqrt((m1['x'] - m2['x'])**2 + (m1['y'] - m2['y'])**2)
                        angle_diff = abs(m1['angle'] - m2['angle'])
                        
                        if pos_dist <= 15 and angle_diff <= 20:
                            match_score = (1.0 - pos_dist/15) * (1.0 - angle_diff/20)
                            best_match = max(best_match, match_score)
                
                if best_match > 0.6:
                    matches += best_match
            
            # Calculate confidence
            confidence = matches / total_comparisons if total_comparisons > 0 else 0.0
            
            # Apply quality factors
            stored_quality = stored_fp.get('quality_score', 0.8)
            live_quality = live_fp.get('quality_score', 0.8)
            quality_factor = min(stored_quality, live_quality)
            
            return min(confidence * quality_factor, 0.99)
            
        except Exception as e:
            self.logger.error(f"Fingerprint matching error: {e}")
            return 0.0
    
    def detect_face(self, image):
        """Detect face in image"""
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
            
            # Use Haar cascade for face detection
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            
            faces = face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(50, 50)
            )
            
            if len(faces) > 0:
                # Return the largest face
                largest_face = max(faces, key=lambda x: x[2] * x[3])
                x, y, w, h = largest_face
                
                # Extract face with padding
                padding = int(min(w, h) * 0.1)
                x1 = max(0, x - padding)
                y1 = max(0, y - padding)
                x2 = min(image.shape[1], x + w + padding)
                y2 = min(image.shape[0], y + h + padding)
                
                face_region = image[y1:y2, x1:x2]
                face_resized = cv2.resize(face_region, (128, 128))
                
                return face_resized
            
            return None
            
        except Exception as e:
            self.logger.error(f"Face detection error: {e}")
            return None
    
    def match_faces(self, stored_photo, live_photo):
        """Match faces in two photos"""
        try:
            stored_face = self.detect_face(stored_photo)
            live_face = self.detect_face(live_photo)
            
            if stored_face is None or live_face is None:
                return 0.0
            
            # Convert to grayscale for comparison
            stored_gray = cv2.cvtColor(stored_face, cv2.COLOR_RGB2GRAY)
            live_gray = cv2.cvtColor(live_face, cv2.COLOR_RGB2GRAY)
            
            # Resize to same size
            live_gray = cv2.resize(live_gray, (stored_gray.shape[1], stored_gray.shape[0]))
            
            # Calculate similarity using template matching
            result = cv2.matchTemplate(stored_gray, live_gray, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, _ = cv2.minMaxLoc(result)
            
            # Calculate histogram similarity
            hist1 = cv2.calcHist([stored_gray], [0], None, [256], [0, 256])
            hist2 = cv2.calcHist([live_gray], [0], None, [256], [0, 256])
            
            cv2.normalize(hist1, hist1, 0, 1, cv2.NORM_MINMAX)
            cv2.normalize(hist2, hist2, 0, 1, cv2.NORM_MINMAX)
            
            hist_correlation = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
            
            # Combine scores
            combined_score = (max_val * 0.6 + hist_correlation * 0.4)
            
            return max(0.0, min(combined_score, 0.99))
            
        except Exception as e:
            self.logger.error(f"Face matching error: {e}")
            return 0.0
    
    def image_to_blob(self, image_array):
        """Convert image array to blob for database storage"""
        _, buffer = cv2.imencode('.jpg', cv2.cvtColor(image_array, cv2.COLOR_RGB2BGR))
        return buffer.tobytes()
    
    def blob_to_image(self, blob_data):
        """Convert blob data back to image array"""
        nparr = np.frombuffer(blob_data, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    
    def fingerprint_to_blob(self, fingerprint_data):
        """Convert fingerprint data to blob for database storage"""
        json_data = json.dumps(fingerprint_data, default=str)
        return json_data.encode('utf-8')
    
    def blob_to_fingerprint(self, blob_data):
        """Convert blob data back to fingerprint data"""
        json_data = blob_data.decode('utf-8')
        return json.loads(json_data)
    
    def validate_photo_quality(self, photo):
        """Validate photo quality"""
        try:
            if photo.shape[0] < 100 or photo.shape[1] < 100:
                return False
            
            # Check if face is detectable
            face = self.detect_face(photo)
            return face is not None
            
        except Exception:
            return False
    
    def validate_fingerprint_quality(self, fp_data):
        """Validate fingerprint quality"""
        try:
            quality_score = fp_data.get('quality_score', 0.0)
            minutiae_count = len(fp_data.get('minutiae', []))
            
            return quality_score >= 0.6 and minutiae_count >= 12
            
        except Exception:
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        if self.camera is not None:
            self.camera.release()
            self.camera = None

# =============================================================================
# GUI APPLICATION
# =============================================================================

class BiometricVerificationSystem:
    """Main application class"""
    
    def __init__(self):
        # Setup logging first
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = Config()
        
        # Initialize components
        self.db_manager = DatabaseManager(self.config.database_path)
        self.biometric_processor = BiometricProcessor(self.config)
        
        # GUI components
        self.root = tk.Tk()
        self.setup_window()
        self.create_interface()
        
        # Current data
        self.current_fingerprint = None
        self.current_photo = None
        self.current_student = None
        
        self.logger.info("Biometric Verification System initialized")
    
    def setup_window(self):
        """Setup main window properties"""
        self.root.title("Biometric Student Verification System")
        self.root.geometry(f"{self.config.window_width}x{self.config.window_height}")
        self.root.configure(bg='#f0f0f0')
        
        # Center window
        self.center_window()
        
        # Configure window close behavior
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width - self.config.window_width) // 2
        y = (screen_height - self.config.window_height) // 2
        
        self.root.geometry(f"{self.config.window_width}x{self.config.window_height}+{x}+{y}")
    
    def create_interface(self):
        """Create the main interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_enrollment_tab()
        self.create_verification_tab()
        self.create_admin_tab()
    
    def create_enrollment_tab(self):
        """Create enrollment tab for registering new students"""
        enrollment_frame = ttk.Frame(self.notebook)
        self.notebook.add(enrollment_frame, text="Student Enrollment")
        
        # Configure grid
        enrollment_frame.grid_rowconfigure(0, weight=1)
        enrollment_frame.grid_columnconfigure(0, weight=1)
        enrollment_frame.grid_columnconfigure(1, weight=1)
        
        # Left panel for student info
        left_panel = ttk.Frame(enrollment_frame)
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(10, 5), pady=10)
        
        # Right panel for preview
        right_panel = ttk.Frame(enrollment_frame)
        right_panel.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)
        
        # Title
        ttk.Label(left_panel, text="Student Enrollment", 
                 font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Student information form
        info_frame = ttk.LabelFrame(left_panel, text="Student Information")
        info_frame.pack(fill='x', pady=(0, 20))
        info_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text="Student ID:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.student_id_entry = ttk.Entry(info_frame, width=30)
        self.student_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(info_frame, text="Full Name:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.student_name_entry = ttk.Entry(info_frame, width=30)
        self.student_name_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(info_frame, text="Email:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.student_email_entry = ttk.Entry(info_frame, width=30)
        self.student_email_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        
        # Biometric capture section
        biometric_frame = ttk.LabelFrame(left_panel, text="Biometric Data Capture")
        biometric_frame.pack(fill='x', pady=(0, 20))
        
        # Fingerprint section
        fp_frame = ttk.Frame(biometric_frame)
        fp_frame.pack(fill='x', pady=5)
        
        ttk.Button(fp_frame, text="📋 Capture Fingerprint", 
                  command=self.capture_fingerprint).pack(side='left', padx=5)
        self.fp_status_label = ttk.Label(fp_frame, text="No fingerprint captured", 
                                        foreground='red')
        self.fp_status_label.pack(side='left', padx=10)
        
        # Photo section
        photo_frame = ttk.Frame(biometric_frame)
        photo_frame.pack(fill='x', pady=5)
        
        ttk.Button(photo_frame, text="📷 Capture Photo", 
                  command=self.capture_photo).pack(side='left', padx=5)
        ttk.Button(photo_frame, text="📁 Upload Photo", 
                  command=self.upload_photo).pack(side='left', padx=5)
        self.photo_status_label = ttk.Label(photo_frame, text="No photo captured", 
                                           foreground='red')
        self.photo_status_label.pack(side='left', padx=10)
        
        # Enrollment buttons
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="✅ Enroll Student", 
                  command=self.enroll_student).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑️ Clear Form", 
                  command=self.clear_enrollment_form).pack(side='left', padx=5)
        
        # Right panel - preview
        ttk.Label(right_panel, text="Biometric Preview", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Photo preview
        self.photo_preview_frame = ttk.LabelFrame(right_panel, text="Student Photo")
        self.photo_preview_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.photo_preview_label = ttk.Label(self.photo_preview_frame, text="No photo")
        self.photo_preview_label.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Fingerprint status
        self.fp_preview_frame = ttk.LabelFrame(right_panel, text="Fingerprint Status")
        self.fp_preview_frame.pack(fill='x')
        
        self.fp_preview_label = ttk.Label(self.fp_preview_frame, text="No fingerprint data")
        self.fp_preview_label.pack(padx=20, pady=20)
    
    def create_verification_tab(self):
        """Create verification tab for exam hall entry"""
        verification_frame = ttk.Frame(self.notebook)
        self.notebook.add(verification_frame, text="Exam Verification")
        
        # Configure grid
        verification_frame.grid_rowconfigure(1, weight=1)
        verification_frame.grid_columnconfigure(0, weight=1)
        

        #
