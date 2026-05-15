'use strict';

  /* ── Fade-in on scroll ── */
  function initFadeIn() {
    var els = document.querySelectorAll('.fade-in');
    if (!els.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('visible'); io.unobserve(e.target); }
      });
    }, { threshold: 0.12 });
    els.forEach(function (el) { io.observe(el); });
  }

  /* ── Tab switcher ── */
  function initTabs() {
    document.querySelectorAll('.tabs').forEach(function (tabs) {
      tabs.querySelectorAll('.tab-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var target = btn.dataset.tab;
          tabs.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.toggle('active', b === btn); });
          var section = tabs.closest('section') || document;
          section.querySelectorAll('.tab-content').forEach(function (tc) {
            tc.classList.toggle('active', tc.id === 'tab-' + target);
          });
        });
      });
    });
  }

  /* ── Copy buttons (uses data-copy-text for clean content) ── */
  function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var block = btn.closest('.code-block');
        var text = block && block.dataset.copyText
          ? block.dataset.copyText
          : (block ? block.querySelector('.code-body').innerText.replace(/\n{3,}/g, '\n\n').trim() : '');
        if (!text) return;
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1800);
        }).catch(function () {
          var ta = document.createElement('textarea');
          ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); } catch (e) { /* ignore */ }
          document.body.removeChild(ta);
          btn.textContent = 'Copied!'; btn.classList.add('copied');
          setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1800);
        });
      });
    });
  }

  /* ── Generic text copy helper ── */
  window.copyText = function (btn, text) {
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = 'Copied!'; btn.classList.add('copied');
      setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1800);
    }).catch(function () {});
  };

  /* ── Npm copy in hero (kept for compat) ── */
  window.copyNpm = function (btn) { window.copyText(btn, 'npm install -g vibecop'); };

  /* ── FAQ accordion ── */
  function initFaq() {
    document.querySelectorAll('.faq-question').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var item = btn.closest('.faq-item');
        var isOpen = item.classList.contains('open');
        document.querySelectorAll('.faq-item').forEach(function (i) { i.classList.remove('open'); });
        if (!isOpen) item.classList.add('open');
      });
    });
  }

  /* ── Smooth scroll ── */
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        var id = a.getAttribute('href').slice(1);
        if (!id) return;
        var el = document.getElementById(id);
        if (!el) return;
        e.preventDefault();
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        var menu = document.getElementById('nav-menu');
        if (menu) menu.classList.remove('open');
      });
    });
  }

  /* ── Active nav on scroll ── */
  function initNavHighlight() {
    var sections = document.querySelectorAll('section[id], div[id]');
    var links = document.querySelectorAll('.navbar-links a[href^="#"]');
    if (!links.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          links.forEach(function (l) {
            l.style.color = l.getAttribute('href') === '#' + e.target.id ? 'var(--text)' : '';
          });
        }
      });
    }, { rootMargin: '-40% 0px -55% 0px' });
    sections.forEach(function (s) { io.observe(s); });
  }

  /* ── Mobile nav ── */
  function initMobileNav() {
    var toggle = document.getElementById('nav-toggle');
    var menu = document.getElementById('nav-menu');
    if (!toggle || !menu) return;
    toggle.addEventListener('click', function () { menu.classList.toggle('open'); });
    document.addEventListener('click', function (e) {
      if (!toggle.contains(e.target) && !menu.contains(e.target)) menu.classList.remove('open');
    });
  }

  /* ── Terminal cursor blink ── */
  function initCursor() {
    var cursor = document.querySelector('.t-cmd');
    if (!cursor) return;
    setInterval(function () { cursor.style.opacity = cursor.style.opacity === '0' ? '1' : '0'; }, 600);
  }

  /* ── OS-aware download ── */
  window.downloadInstaller = function () {
    var ua = navigator.userAgent || navigator.platform || '';
    var isWin = /Win/i.test(ua);
    var isMac = /Mac/i.test(ua);
    var file = isWin ? 'install-vibecop.bat' : 'install-vibecop.sh';
    var label = document.getElementById('hero-download-label');
    if (label) {
      var origLabel = label.textContent || '';
      label.textContent = 'Downloading…';
      setTimeout(function () { label.textContent = origLabel; }, 2500);
    }
    var a = document.createElement('a');
    a.href = file; a.download = file;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
  };

  /* ── Boot ── */
  document.addEventListener('DOMContentLoaded', function () {
    initFadeIn();
    initTabs();
    initCopyButtons();
    initFaq();
    initSmoothScroll();
    initNavHighlight();
    initMobileNav();
    initCursor();
    /* Download button label by OS */
    var dlLabel = document.getElementById('hero-download-label');
    if (dlLabel) {
      var ua = navigator.userAgent || '';
      if (/Mac/i.test(ua)) dlLabel.textContent = 'Download for macOS';
      else if (!/Win/i.test(ua)) dlLabel.textContent = 'Download for Linux';
    }
  });
