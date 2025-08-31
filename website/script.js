// Deadbolt 5 - Interactive Website JavaScript

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initParticleSystem();
    init3DShield();
    initCounterAnimations();
    initSmoothScrolling();
    initDemoSimulation();
    initDashboardUpdates();
    initMobileMenu();
});

// Particle System for Background
function initParticleSystem() {
    const canvas = document.getElementById('particles-canvas');
    const ctx = canvas.getContext('2d');
    
    // Set canvas size
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    // Particle array
    const particles = [];
    const maxParticles = 100;
    
    // Particle class
    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 0.5;
            this.vy = (Math.random() - 0.5) * 0.5;
            this.size = Math.random() * 2 + 1;
            this.opacity = Math.random() * 0.5 + 0.2;
            this.color = Math.random() > 0.5 ? '#00ffff' : '#ff00ff';
        }
        
        update() {
            this.x += this.vx;
            this.y += this.vy;
            
            // Wrap around edges
            if (this.x < 0) this.x = canvas.width;
            if (this.x > canvas.width) this.x = 0;
            if (this.y < 0) this.y = canvas.height;
            if (this.y > canvas.height) this.y = 0;
        }
        
        draw() {
            ctx.save();
            ctx.globalAlpha = this.opacity;
            ctx.fillStyle = this.color;
            ctx.shadowColor = this.color;
            ctx.shadowBlur = 5;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        }
    }
    
    // Create particles
    for (let i = 0; i < maxParticles; i++) {
        particles.push(new Particle());
    }
    
    // Animation loop
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Update and draw particles
        particles.forEach(particle => {
            particle.update();
            particle.draw();
        });
        
        // Draw connections between nearby particles
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 100) {
                    ctx.save();
                    ctx.globalAlpha = (100 - distance) / 100 * 0.2;
                    ctx.strokeStyle = '#00ffff';
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                    ctx.restore();
                }
            }
        }
        
        requestAnimationFrame(animate);
    }
    
    animate();
}

// 3D Shield Animation using Three.js
function init3DShield() {
    const container = document.getElementById('shield-3d');
    if (!container) return;
    
    // Scene setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, 1, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    
    renderer.setSize(400, 400);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    
    // Create shield geometry
    const shieldGeometry = new THREE.SphereGeometry(2, 32, 32);
    const shieldMaterial = new THREE.MeshBasicMaterial({
        color: 0x00ffff,
        wireframe: true,
        transparent: true,
        opacity: 0.3
    });
    const shield = new THREE.Mesh(shieldGeometry, shieldMaterial);
    scene.add(shield);
    
    // Create inner core
    const coreGeometry = new THREE.SphereGeometry(1, 16, 16);
    const coreMaterial = new THREE.MeshBasicMaterial({
        color: 0xff00ff,
        transparent: true,
        opacity: 0.6
    });
    const core = new THREE.Mesh(coreGeometry, coreMaterial);
    scene.add(core);
    
    // Create orbiting particles
    const particles = [];
    for (let i = 0; i < 20; i++) {
        const particleGeometry = new THREE.SphereGeometry(0.05, 8, 8);
        const particleMaterial = new THREE.MeshBasicMaterial({
            color: Math.random() > 0.5 ? 0x00ff41 : 0xff8800
        });
        const particle = new THREE.Mesh(particleGeometry, particleMaterial);
        
        // Random orbit position
        const radius = 3 + Math.random() * 2;
        const angle = Math.random() * Math.PI * 2;
        const height = (Math.random() - 0.5) * 4;
        
        particle.userData = {
            radius: radius,
            angle: angle,
            height: height,
            speed: 0.01 + Math.random() * 0.02
        };
        
        particles.push(particle);
        scene.add(particle);
    }
    
    camera.position.z = 8;
    
    // Animation loop
    function animate() {
        requestAnimationFrame(animate);
        
        // Rotate shield
        shield.rotation.x += 0.005;
        shield.rotation.y += 0.01;
        
        // Pulse core
        const scale = 1 + Math.sin(Date.now() * 0.005) * 0.2;
        core.scale.set(scale, scale, scale);
        core.rotation.x += 0.01;
        core.rotation.y -= 0.01;
        
        // Animate particles
        particles.forEach(particle => {
            particle.userData.angle += particle.userData.speed;
            particle.position.x = Math.cos(particle.userData.angle) * particle.userData.radius;
            particle.position.z = Math.sin(particle.userData.angle) * particle.userData.radius;
            particle.position.y = particle.userData.height + Math.sin(particle.userData.angle * 3) * 0.5;
        });
        
        renderer.render(scene, camera);
    }
    
    animate();
}

// Counter Animations
function initCounterAnimations() {
    const counters = document.querySelectorAll('.stat-number');
    
    const animateCounter = (counter) => {
        const target = parseFloat(counter.getAttribute('data-target'));
        const increment = target / 100;
        let current = 0;
        
        const updateCounter = () => {
            if (current < target) {
                current += increment;
                if (current > target) current = target;
                
                if (target % 1 === 0) {
                    counter.textContent = Math.floor(current);
                } else {
                    counter.textContent = current.toFixed(1);
                }
                
                requestAnimationFrame(updateCounter);
            }
        };
        
        updateCounter();
    };
    
    // Intersection Observer for triggering animations
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                observer.unobserve(entry.target);
            }
        });
    });
    
    counters.forEach(counter => observer.observe(counter));
}

// Smooth Scrolling
function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Demo Simulation
function initDemoSimulation() {
    const startBtn = document.getElementById('startSimulation');
    const demoStatus = document.getElementById('demoStatus');
    const fileSystem = document.querySelector('.file-grid');
    const timelineEvents = document.querySelector('.timeline-events');
    
    if (!startBtn) return;
    
    // Create file grid
    function createFileGrid() {
        fileSystem.innerHTML = '';
        for (let i = 0; i < 100; i++) {
            const file = document.createElement('div');
            file.className = 'file-item';
            file.style.animationDelay = `${i * 10}ms`;
            fileSystem.appendChild(file);
        }
    }
    
    // Add timeline event
    function addTimelineEvent(message, type = 'info') {
        const event = document.createElement('div');
        event.className = `timeline-event ${type}`;
        event.textContent = `${new Date().toLocaleTimeString()}: ${message}`;
        timelineEvents.insertBefore(event, timelineEvents.firstChild);
        
        // Keep only last 10 events
        while (timelineEvents.children.length > 10) {
            timelineEvents.removeChild(timelineEvents.lastChild);
        }
    }
    
    // Simulation function
    function runSimulation() {
        createFileGrid();
        
        // Update status
        const statusDot = demoStatus.querySelector('.status-dot');
        const statusText = demoStatus.querySelector('span');
        statusDot.className = 'status-dot online';
        statusText.textContent = 'Simulation running...';
        
        addTimelineEvent('Deadbolt system initialized', 'info');
        addTimelineEvent('File system monitoring started', 'info');
        
        // Simulate ransomware attack
        setTimeout(() => {
            addTimelineEvent('Suspicious process detected: malware.exe', 'threat');
            
            // Start "encrypting" files
            const files = document.querySelectorAll('.file-item');
            let encryptedCount = 0;
            
            const encryptInterval = setInterval(() => {
                if (encryptedCount < 8) { // Only encrypt 8 files before being stopped
                    files[encryptedCount].classList.add('encrypted');
                    encryptedCount++;
                    addTimelineEvent(`File ${encryptedCount} encrypted`, 'threat');
                } else {
                    clearInterval(encryptInterval);
                    
                    // Deadbolt response
                    setTimeout(() => {
                        addTimelineEvent('RANSOMWARE DETECTED! Initiating response', 'blocked');
                        addTimelineEvent('Process malware.exe terminated', 'blocked');
                        addTimelineEvent('File encryption stopped', 'blocked');
                        addTimelineEvent('System protected - 92 files saved', 'blocked');
                        
                        // Protect remaining files
                        for (let i = encryptedCount; i < files.length; i++) {
                            setTimeout(() => {
                                files[i].classList.add('protected');
                            }, (i - encryptedCount) * 20);
                        }
                        
                        // Update status
                        statusDot.className = 'status-dot online';
                        statusText.textContent = 'Simulation complete - Threat blocked!';
                        
                    }, 1000);
                }
            }, 200);
            
        }, 2000);
    }
    
    startBtn.addEventListener('click', runSimulation);
    
    // Initialize with empty grid
    createFileGrid();
}

// Dashboard Updates
function initDashboardUpdates() {
    // Simulate real-time updates
    setInterval(() => {
        // Update threat counter
        const threatsBlocked = document.getElementById('threatsBlocked');
        if (threatsBlocked) {
            const current = parseInt(threatsBlocked.textContent.replace(',', ''));
            threatsBlocked.textContent = (current + Math.floor(Math.random() * 3)).toLocaleString();
        }
        
        // Update response time
        const responseTime = document.getElementById('avgResponseTime');
        if (responseTime) {
            const variation = (Math.random() - 0.5) * 0.4;
            const newTime = Math.max(1.8, Math.min(2.8, 2.3 + variation));
            responseTime.textContent = newTime.toFixed(1) + 's';
        }
        
        // Update performance meters
        const meters = document.querySelectorAll('.meter-fill');
        meters.forEach(meter => {
            const currentWidth = parseInt(meter.style.width) || 15;
            const variation = (Math.random() - 0.5) * 10;
            const newWidth = Math.max(5, Math.min(50, currentWidth + variation));
            meter.style.width = newWidth + '%';
            meter.parentElement.nextElementSibling.textContent = Math.round(newWidth) + '%';
        });
        
    }, 3000);
}

// Mobile Menu
function initMobileMenu() {
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    
    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });
        
        // Close menu when clicking on a link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                hamburger.classList.remove('active');
                navMenu.classList.remove('active');
            });
        });
    }
}

// Utility Functions
function startDemo() {
    document.getElementById('demo').scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => {
        document.getElementById('startSimulation').click();
    }, 1000);
}

function downloadDeadbol() {
    // Simulate download
    const btn = event.target.closest('.btn');
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '<span>📥</span><span>Preparing download...</span>';
    btn.disabled = true;
    
    setTimeout(() => {
        btn.innerHTML = '<span>✅</span><span>Download started!</span>';
        
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }, 2000);
    }, 1500);
}

// Add some interactive hover effects
document.addEventListener('mousemove', (e) => {
    const cursor = { x: e.clientX, y: e.clientY };
    
    // Add glow effect to feature cards
    document.querySelectorAll('.feature-card').forEach(card => {
        const rect = card.getBoundingClientRect();
        const cardCenter = {
            x: rect.left + rect.width / 2,
            y: rect.top + rect.height / 2
        };
        
        const distance = Math.sqrt(
            Math.pow(cursor.x - cardCenter.x, 2) + 
            Math.pow(cursor.y - cardCenter.y, 2)
        );
        
        if (distance < 200) {
            const intensity = (200 - distance) / 200;
            card.style.boxShadow = `0 0 ${20 + intensity * 30}px rgba(0, 255, 255, ${0.3 + intensity * 0.4})`;
        } else {
            card.style.boxShadow = '';
        }
    });
});

// Add typing effect to hero description
function typeWriter(element, text, speed = 50) {
    let i = 0;
    element.innerHTML = '';
    
    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    
    type();
}

// Initialize typing effect when hero section is visible
const heroObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const description = document.querySelector('.hero-description');
            if (description && !description.dataset.typed) {
                const text = description.textContent;
                description.dataset.typed = 'true';
                typeWriter(description, text, 30);
            }
        }
    });
});

const heroSection = document.querySelector('.hero');
if (heroSection) {
    heroObserver.observe(heroSection);
}