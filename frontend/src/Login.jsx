import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { Eye, EyeOff, CheckCircle2, XCircle, LogIn } from 'lucide-react';
import { auth } from './firebase';
import { createUserWithEmailAndPassword, signInWithEmailAndPassword } from 'firebase/auth';

const Login = () => {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    age: '',
    occupation: '',
    location: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  // Custom styled toast
  const showToast = (msg, type = 'info') => {
    // Always use green for 'success', red for 'error', blue for info/other
    let bg = '#4285F4';
    if (type === 'success') bg = '#388e3c';
    if (type === 'error') bg = '#d32f2f';
    toast(
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        color: '#fff',
        background: bg,
        borderRadius: 6,
        padding: '12px 18px',
        minWidth: 220,
        boxShadow: '0 2px 8px rgba(0,0,0,0.12)',
        fontWeight: 500
      }}>
        {type === 'success' && <CheckCircle2 size={22} color="#fff" style={{ flexShrink: 0 }} />}
        {type === 'error' && <XCircle size={22} color="#fff" style={{ flexShrink: 0 }} />}
        <div>{msg}</div>
      </div>,
      {
        position: 'top-right',
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        autoClose: 3000,
        style: { background: 'transparent', boxShadow: 'none', padding: 0 },
        bodyStyle: { padding: 0, margin: 0 }
      }
    );
  };

  // Handle direct login for demo purposes
  const handleDemoLogin = async () => {
    setIsLoading(true);
    
    try {
      // Demo credentials
      const demoEmail = "demo@harmonymatch.com";
      const demoPassword = "demo123";
      
      // Use the existing login endpoint
      const res = await fetch("http://localhost:8000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          username: demoEmail,
          password: demoPassword,
        }),
      });
      
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.detail || "Demo login failed");
      
      // Store auth data in localStorage
      localStorage.setItem("token", data.access_token);
      localStorage.setItem("user", JSON.stringify(data.user));
      
      showToast("Demo login successful!", "success");
      
      // Redirect to dashboard after successful login
      setTimeout(() => {
        navigate('/dashboard');
      }, 1000);
    } catch (err) {
      showToast(err.message || "Demo login failed", "error");
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e) => {
  e.preventDefault();
  setIsLoading(true);

  if (isLogin) {
    // LOGIN WITH FIREBASE
    try {
      const userCredential = await signInWithEmailAndPassword(auth, formData.email, formData.password);
      const user = userCredential.user;

      showToast("Login successful!", "success");

      // Save Firebase ID token (optional)
      const token = await user.getIdToken();
      localStorage.setItem("token", token);
      localStorage.setItem("user", JSON.stringify({
        uid: user.uid,
        email: user.email,
      }));

      setTimeout(() => navigate('/dashboard'), 1000);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setIsLoading(false);
    }
  } else {
    // SIGNUP WITH FIREBASE
    if (formData.password !== formData.confirmPassword) {
      showToast("Passwords do not match", "error");
      setIsLoading(false);
      return;
    }

    try {
      const userCredential = await createUserWithEmailAndPassword(auth, formData.email, formData.password);
      const user = userCredential.user;

      showToast("Signup successful! Please login.", "success");
      setIsLogin(true);

      // Optionally store user info in Firestore
      // (Not implemented here)

      // Clear form except email
      const email = formData.email;
      setFormData({
        name: '',
        email: email,
        password: '',
        confirmPassword: '',
        age: '',
        occupation: '',
        location: ''
      });
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setIsLoading(false);
    }
  }
};

  const WomenSilhouetteSVG = () => (
    <svg viewBox="0 0 400 300" style={{ width: '100%', height: '200px' }}>
      <defs>
        <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3949ab" />
          <stop offset="50%" stopColor="#7986cb" />
          <stop offset="100%" stopColor="#c5cae9" />
        </linearGradient>
        <linearGradient id="gradient2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#c5cae9" />
          <stop offset="100%" stopColor="#7986cb" />
        </linearGradient>
      </defs>
      
      {/* Background circles */}
      <circle cx="100" cy="150" r="80" fill="#c5cae9" opacity="0.6" />
      <circle cx="300" cy="100" r="60" fill="#7986cb" opacity="0.4" />
      
      {/* Woman silhouettes */}
      <g transform="translate(50, 80)">
        <path d="M50 40 C50 20, 70 10, 90 40 L90 60 C90 80, 80 90, 70 100 L70 180 L30 180 L30 100 C20 90, 10 80, 10 60 L10 40 Z" 
              fill="#3949ab" opacity="0.9" />
      </g>
      
      <g transform="translate(150, 60)">
        <path d="M40 30 C40 15, 55 5, 75 30 L75 50 C75 70, 65 80, 55 90 L55 170 L25 170 L25 90 C15 80, 5 70, 5 50 L5 30 Z" 
              fill="#7986cb" opacity="0.8" />
      </g>
      
      <g transform="translate(250, 90)">
        <path d="M45 35 C45 18, 62 8, 82 35 L82 55 C82 75, 72 85, 62 95 L62 175 L28 175 L28 95 C18 85, 8 75, 8 55 L8 35 Z" 
              fill="#c5cae9" opacity="0.7" />
      </g>
    </svg>
  );

  const HomeSVG = () => (
    <svg viewBox="0 0 200 200" style={{ width: '60px', height: '60px', marginBottom: '20px' }}>
      <defs>
        <linearGradient id="homeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#c5cae9" />
          <stop offset="100%" stopColor="#7986cb" />
        </linearGradient>
      </defs>
      
      <path d="M100 20 L170 80 L170 170 L30 170 L30 80 Z" fill="#c5cae9" opacity="0.9" />
      <rect x="60" y="120" width="30" height="40" fill="#3949ab" opacity="0.8" />
      <rect x="110" y="100" width="25" height="25" fill="#3949ab" opacity="0.8" />
      <rect x="140" y="100" width="25" height="25" fill="#3949ab" opacity="0.8" />
      <path d="M100 20 L170 80 L30 80 Z" fill="#3949ab" />
    </svg>
  );

  return (
    <div style={styles.container}>
      <div style={styles.leftPanel}>
        <div style={styles.brandSection}>
          <HomeSVG />
          <h1 style={styles.brandTitle}>Sakhi</h1>
          <p style={styles.brandSubtitle}>Find Your Perfect Female Roommate</p>
        </div>
        
        <div style={styles.illustrationContainer}>
          <WomenSilhouetteSVG />
        </div>
        
        <div style={styles.features}>
          <div style={styles.feature}>
            <div style={styles.featureIcon}>🏠</div>
            <span>Safe & Verified Listings</span>
          </div>
          <div style={styles.feature}>
            <div style={styles.featureIcon}>👥</div>
            <span>Women-Only Community</span>
          </div>
          <div style={styles.feature}>
            <div style={styles.featureIcon}>🔒</div>
            <span>Privacy Protected</span>
          </div>
          <div style={styles.feature}>
            <div style={styles.featureIcon}>🏆</div>
            <span>Team 404 Girls Found</span>
          </div>
        </div>
      </div>

      <div style={styles.rightPanel}>
        <div style={styles.authContainer}>
          <div style={styles.toggleContainer}>
            <button
              style={{
                ...styles.toggleButton,
                ...(isLogin ? styles.activeToggle : styles.inactiveToggle)
              }}
              onClick={() => setIsLogin(true)}
            >
              Login
            </button>
            <button
              style={{
                ...styles.toggleButton,
                ...(isLogin ? styles.inactiveToggle : styles.activeToggle)
              }}
              onClick={() => setIsLogin(false)}
            >
              Sign Up
            </button>
          </div>

          <div style={styles.formContainer}>
            <h2 style={styles.formTitle}>
              {isLogin ? 'Welcome' : 'Join Our Community'}
            </h2>
            <p style={styles.formSubtitle}>
              {isLogin 
                ? 'Sign in to find your perfect roommate' 
                : 'Create your account to get started'}
            </p>

            <div style={styles.form}>
              {!isLogin && (
                <div style={styles.inputGroup}>
                  <input
                    type="text"
                    name="name"
                    placeholder="Full Name"
                    value={formData.name}
                    onChange={handleInputChange}
                    style={styles.input}
                    required
                  />
                </div>
              )}

              <div style={styles.inputGroup}>
                <input
                  type="email"
                  name="email"
                  placeholder="Email Address"
                  value={formData.email}
                  onChange={handleInputChange}
                  style={styles.input}
                  required
                />
              </div>

              <div style={styles.inputGroup}>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    placeholder="Password"
                    value={formData.password}
                    onChange={handleInputChange}
                    style={styles.input}
                    required
                  />
                  <span
                    onClick={() => setShowPassword((v) => !v)}
                    style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', cursor: 'pointer', color: '#3949ab' }}
                  >
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </span>
                </div>
              </div>

              {!isLogin && (
                <>
                  <div style={styles.inputGroup}>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showConfirmPassword ? 'text' : 'password'}
                        name="confirmPassword"
                        placeholder="Confirm Password"
                        value={formData.confirmPassword}
                        onChange={handleInputChange}
                        style={styles.input}
                        required
                      />
                      <span
                        onClick={() => setShowConfirmPassword((v) => !v)}
                        style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', cursor: 'pointer', color: '#3949ab' }}
                      >
                        {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                      </span>
                    </div>
                  </div>

                  <div style={styles.row}>
                    <div style={styles.inputGroup}>
                      <input
                        type="number"
                        name="age"
                        placeholder="Age"
                        value={formData.age}
                        onChange={handleInputChange}
                        style={styles.input}
                        required
                      />
                    </div>
                    <div style={styles.inputGroup}>
                      <input
                        type="text"
                        name="occupation"
                        placeholder="Occupation"
                        value={formData.occupation}
                        onChange={handleInputChange}
                        style={styles.input}
                        required
                      />
                    </div>
                  </div>

                  <div style={styles.inputGroup}>
                    <input
                      type="text"
                      name="location"
                      placeholder="Preferred Location"
                      value={formData.location}
                      onChange={handleInputChange}
                      style={styles.input}
                      required
                    />
                  </div>
                </>
              )}

              {isLogin && (
                <div style={styles.forgotPassword}>
                  <a href="#" style={styles.forgotLink}>Forgot Password?</a>
                </div>
              )}

              <button 
                type="button" 
                onClick={handleSubmit} 
                disabled={isLoading}
                style={{
                  ...styles.submitButton,
                  ...(isLoading && styles.loadingButton)
                }}
              >
                {isLoading ? (
                  <div style={styles.loadingSpinner}>
                    <div style={styles.spinner}></div>
                    <span>{isLogin ? 'Signing in...' : 'Creating account...'}</span>
                  </div>
                ) : (
                  <>{isLogin ? 'Sign In' : 'Create Account'}</>
                )}
              </button>
              
              {/* Direct login button - Only show on login screen */}
              {isLogin && (
                <button 
                  type="button" 
                  onClick={handleDemoLogin} 
                  disabled={isLoading}
                  style={{
                    ...styles.directLoginButton,
                    ...(isLoading && styles.loadingButton)
                  }}
                >
                  {isLoading ? (
                    <div style={styles.loadingSpinner}>
                      <div style={styles.spinner}></div>
                      <span>Logging in...</span>
                    </div>
                  ) : (
                    <div style={styles.buttonContent}>
                      <LogIn size={18} />
                      <span>Quick Demo Access</span>
                    </div>
                  )}
                </button>
              )}
            </div>

            <p style={styles.termsText}>
              By {isLogin ? 'signing in' : 'signing up'}, you agree to our{' '}
              <a href="#" style={styles.link}>Terms of Service</a> and{' '}
              <a href="#" style={styles.link}>Privacy Policy</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    minHeight: '100vh',
    fontFamily: '"Segoe UI", Tahoma, Geneva, Verdana, sans-serif',
    backgroundColor: '#3949ab'
  },
  leftPanel: {
    flex: 1,
    backgroundColor: '#3949ab',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'flex-start', // lift content up
    alignItems: 'center',
    padding: '40px',
    position: 'relative',
    overflow: 'hidden',
    paddingTop: '60px', // add extra top padding
  },
  brandSection: {
    textAlign: 'center',
    marginBottom: '40px'
  },
  brandTitle: {
    fontSize: '2.5rem',
    fontWeight: '700',
    color: 'white',
    margin: '0 0 10px 0',
    textShadow: '0 2px 4px rgba(0,0,0,0.3)'
  },
  brandSubtitle: {
    fontSize: '1.1rem',
    color: 'rgba(255,255,255,0.9)',
    margin: 0,
    fontWeight: '300'
  },
  illustrationContainer: {
    marginBottom: '40px',
    maxWidth: '400px',
    width: '100%'
  },
  features: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
    alignItems: 'flex-start'
  },
  feature: {
    display: 'flex',
    alignItems: 'center',
    gap: '15px',
    color: 'white',
    fontSize: '1.1rem',
    fontWeight: '500'
  },
  featureIcon: {
    fontSize: '1.5rem',
    backgroundColor: '#c5cae9',
    color: '#3949ab',
    padding: '10px',
    borderRadius: '50%',
    width: '40px',
    height: '40px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  rightPanel: {
    flex: 1,
    display: 'flex',
    alignItems: 'flex-start', // align content to top
    justifyContent: 'center',
    padding: '40px',
    backgroundColor: '#e8eaf6',
    height: '100vh',
    overflowY: 'auto',
  },
  authContainer: {
    background: 'white',
    borderRadius: '20px',
    padding: '40px',
    width: '100%',
    maxWidth: '450px',
    boxShadow: '0 20px 40px rgba(57, 73, 171, 0.15)',
    border: '2px solid #7986cb',
  },
  toggleContainer: {
    display: 'flex',
    backgroundColor: '#e8eaf6',
    borderRadius: '12px',
    padding: '6px',
    marginBottom: '30px',
    position: 'relative'
  },
  toggleButton: {
    flex: 1,
    padding: '12px 24px',
    border: 'none',
    borderRadius: '8px',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    position: 'relative',
    zIndex: 1
  },
  activeToggle: {
    backgroundColor: '#3949ab',
    color: 'white',
    transform: 'translateY(-2px)',
    boxShadow: '0 4px 12px rgba(57, 73, 171, 0.3)'
  },
  inactiveToggle: {
    backgroundColor: 'transparent',
    color: '#3949ab'
  },
  formContainer: {
    textAlign: 'center'
  },
  formTitle: {
    fontSize: '1.8rem',
    fontWeight: '700',
    color: '#3949ab',
    marginBottom: '8px'
  },
  formSubtitle: {
    color: '#718096',
    marginBottom: '30px',
    fontSize: '1rem'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
    marginBottom: '20px'
  },
  inputGroup: {
    flex: 1
  },
  row: {
    display: 'flex',
    gap: '15px'
  },
  input: {
    width: '100%',
    padding: '15px 20px',
    border: '2px solid #7986cb',
    borderRadius: '12px',
    fontSize: '1rem',
    transition: 'all 0.3s ease',
    outline: 'none',
    boxSizing: 'border-box'
  },
  forgotPassword: {
    textAlign: 'right',
    marginTop: '-10px'
  },
  forgotLink: {
    color: '#3949ab',
    textDecoration: 'none',
    fontSize: '0.9rem',
    fontWeight: '500'
  },
  submitButton: {
    width: '100%',
    padding: '16px',
    backgroundColor: '#3949ab',
    color: 'white',
    border: 'none',
    borderRadius: '12px',
    fontSize: '1.1rem',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    marginTop: '10px'
  },
  directLoginButton: {
    width: '100%',
    padding: '14px',
    marginTop: '12px',
    backgroundColor: '#7986cb',
    color: 'white',
    border: 'none',
    borderRadius: '12px',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px',
    boxShadow: '0 4px 12px rgba(121, 134, 203, 0.3)'
  },
  loadingButton: {
    opacity: 0.8,
    cursor: 'not-allowed'
  },
  buttonContent: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px'
  },
  loadingSpinner: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px'
  },
  spinner: {
    width: '18px',
    height: '18px',
    border: '3px solid rgba(255, 255, 255, 0.3)',
    borderRadius: '50%',
    borderTopColor: 'white',
    animation: 'spin 1s linear infinite'
  },
  termsText: {
    fontSize: '0.85rem',
    color: '#718096',
    lineHeight: '1.5',
    margin: 0
  },
  link: {
    color: '#3949ab',
    textDecoration: 'none',
    fontWeight: '500'
  }
};

// Add keyframes animation for spinner
const styleSheet = document.createElement('style');
styleSheet.textContent = `
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  
  input:focus {
    border-color: #3949ab !important;
    box-shadow: 0 0 0 3px rgba(57, 73, 171, 0.1) !important;
  }
  
  button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 25px rgba(57, 73, 171, 0.2) !important;
  }
  
  .google-button:hover {
    border-color: #3949ab !important;
    background: #fafafa !important;
  }
  
  .submit-button:hover {
    background-color: #303f9f !important;
  }
  
  a:hover {
    text-decoration: underline !important;
  }

  @media (max-width: 768px) {
    .container {
      flex-direction: column !important;
    }
    
    .left-panel {
      min-height: 40vh !important;
      padding: 20px !important;
    }
    
    .right-panel {
      padding: 20px !important;
    }
    
    .auth-container {
      padding: 30px 20px !important;
    }
    
    .row {
      flex-direction: column !important;
      gap: 20px !important;
    }
    
    .brand-title {
      font-size: 2rem !important;
    }
    
    .features {
      flex-direction: row !important;
      flex-wrap: wrap !important;
      justify-content: center !important;
    }
  }
`;
document.head.appendChild(styleSheet);

export default Login;