/* ============================================================
   Animation Engine — Scroll Reveals + Counter + Navbar + Progress
   ============================================================ */
(function () {
  'use strict';
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Delay variables from data attributes (replaces inline style usage) ---
  document.querySelectorAll('[data-delay]').forEach((el) => {
    const raw = parseInt(el.dataset.delay || '', 10);
    if (!Number.isNaN(raw)) {
      el.style.setProperty('--delay', raw + 'ms');
    }
  });

  document.querySelectorAll('[data-pill-delay]').forEach((el) => {
    const raw = parseInt(el.dataset.pillDelay || '', 10);
    if (!Number.isNaN(raw)) {
      el.style.setProperty('--pill-delay', raw + 'ms');
    }
  });

  // --- Scroll Progress + Navbar scroll effect (single rAF listener) ---
  const progressBar = document.querySelector('.scroll-progress');
  const navbar = document.querySelector('.navbar-main');
  if ((progressBar && !prefersReducedMotion) || navbar) {
    let ticking = false;
    const updateScrollState = () => {
      if (progressBar && !prefersReducedMotion) {
        const h = document.documentElement;
        const scrollTop = h.scrollTop || document.body.scrollTop;
        const scrollHeight = h.scrollHeight - h.clientHeight;
        const progress = scrollHeight > 0 ? scrollTop / scrollHeight : 0;
        progressBar.style.transform = 'scaleX(' + progress + ')';
      }
      if (navbar) {
        navbar.classList.toggle('scrolled', window.scrollY > 40);
      }
      ticking = false;
    };
    const onScroll = () => {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(updateScrollState);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    updateScrollState();
  }

  // --- Scroll Reveal via Intersection Observer ---
  const revealEls = document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale');
  if (revealEls.length && !prefersReducedMotion) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('revealed');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    revealEls.forEach(el => io.observe(el));
  } else if (revealEls.length) {
    revealEls.forEach(el => el.classList.add('revealed'));
  }

  // --- Random color for each crossing item ---
  const crossingItems = document.querySelectorAll('.hero-service-pill');
  if (crossingItems.length) {
    const crossingPalettes = [
      { bg: 'rgba(79, 123, 255, 0.12)', border: 'rgba(122, 166, 255, 0.42)', text: '#ccddff', icon: '#7ba6ff' },
      { bg: 'rgba(16, 185, 129, 0.12)', border: 'rgba(52, 211, 153, 0.42)', text: '#c7f7e2', icon: '#34d399' },
      { bg: 'rgba(245, 158, 11, 0.13)', border: 'rgba(251, 191, 36, 0.44)', text: '#ffe5b3', icon: '#fbbf24' },
      { bg: 'rgba(236, 72, 153, 0.12)', border: 'rgba(244, 114, 182, 0.42)', text: '#ffd0e7', icon: '#f472b6' },
      { bg: 'rgba(14, 165, 233, 0.12)', border: 'rgba(56, 189, 248, 0.44)', text: '#ccefff', icon: '#38bdf8' },
      { bg: 'rgba(168, 85, 247, 0.13)', border: 'rgba(192, 132, 252, 0.44)', text: '#e7d2ff', icon: '#c084fc' }
    ];

    crossingItems.forEach((item, index) => {
      const palette = crossingPalettes[index % crossingPalettes.length];
      item.style.setProperty('--pill-bg', palette.bg);
      item.style.setProperty('--pill-border', palette.border);
      item.style.setProperty('--pill-text', palette.text);
      item.style.setProperty('--pill-icon', palette.icon);
    });
  }

  // --- Animated Counters ---
  function animateCounters() {
    document.querySelectorAll('.stat-number[data-target]').forEach(el => {
      if (el.dataset.animated) return;
      el.dataset.animated = '1';
      const target = parseInt(el.dataset.target, 10);
      const suffix = el.dataset.suffix || '';
      if (prefersReducedMotion) {
        el.textContent = target.toLocaleString() + suffix;
        return;
      }
      const duration = 2000;
      const step = target / (duration / 16);
      let current = 0;
      const timer = setInterval(() => {
        current += step;
        if (current >= target) {
          el.textContent = target.toLocaleString() + suffix;
          clearInterval(timer);
        } else {
          el.textContent = Math.floor(current).toLocaleString() + suffix;
        }
      }, 16);
    });
  }
  const statsSection = document.querySelector('.stats-section');
  if (statsSection) {
    const sio = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) { animateCounters(); sio.unobserve(e.target); }
      });
    }, { threshold: 0.3 });
    sio.observe(statsSection);
  }

  // --- Mobile menu toggle (custom hamburger) ---
  const mobileToggle = document.getElementById('mobileMenuToggle');
  const navCollapse = document.getElementById('navbarMainCollapse');
  if (mobileToggle && navCollapse) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = navCollapse.classList.contains('show');
      if (isOpen) {
        navCollapse.classList.remove('show');
        mobileToggle.setAttribute('aria-expanded', 'false');
      } else {
        navCollapse.classList.add('show');
        mobileToggle.setAttribute('aria-expanded', 'true');
      }
    });

    // Close mobile menu when a nav link is clicked
    navCollapse.querySelectorAll('.nav-link:not(.dropdown-toggle)').forEach(link => {
      link.addEventListener('click', () => {
        if (window.innerWidth < 992) {
          navCollapse.classList.remove('show');
          mobileToggle.setAttribute('aria-expanded', 'false');
        }
      });
    });
  }

  // --- Desktop dropdown: click-to-open (no hover) ---
  const dropdownItems = document.querySelectorAll('.navbar-main .nav-item.dropdown');

  // --- Fallback dropdown toggle if Bootstrap dropdown JS is unavailable ---
  if (dropdownItems.length && !window.bootstrap?.Dropdown) {
    const toggles = document.querySelectorAll('.navbar-main .nav-item.dropdown > .dropdown-toggle');
    const closeAll = (exceptItem) => {
      dropdownItems.forEach((item) => {
        if (item === exceptItem) return;
        item.classList.remove('show');
        item.querySelector('.dropdown-menu')?.classList.remove('show');
        item.querySelector('.dropdown-toggle')?.setAttribute('aria-expanded', 'false');
      });
    };

    toggles.forEach((toggle) => {
      toggle.addEventListener('click', (event) => {
        event.preventDefault();
        const item = toggle.closest('.nav-item.dropdown');
        if (!item) return;
        const menu = item.querySelector('.dropdown-menu');
        const shouldOpen = !item.classList.contains('show');
        closeAll(item);
        item.classList.toggle('show', shouldOpen);
        menu?.classList.toggle('show', shouldOpen);
        toggle.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
      });
    });

    document.addEventListener('click', (event) => {
      if (event.target.closest('.navbar-main .nav-item.dropdown')) return;
      closeAll(null);
    });
  }

  // --- Smooth scroll for anchor links ---
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (!href || href === '#') return;
      let target = null;
      try {
        target = document.querySelector(href);
      } catch (err) {
        return;
      }
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'start' });
      }
    });
  });
})();
