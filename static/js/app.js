/* SecureDoc Verify — Frontend JS */

// Active nav link highlighting
document.addEventListener('DOMContentLoaded', () => {
  const path  = window.location.pathname;
  const links = document.querySelectorAll('.nav-link');
  links.forEach(link => {
    const href = link.getAttribute('href');
    if (href && path.startsWith(href) && href !== '/') {
      link.classList.add('active', 'text-white');
    } else if (href === '/' && path === '/') {
      link.classList.add('active', 'text-white');
    }
  });

  // Hash copy on click
  document.querySelectorAll('.hash-display').forEach(el => {
    el.style.cursor = 'pointer';
    el.title = 'Click to copy';
    el.addEventListener('click', () => {
      navigator.clipboard.writeText(el.textContent.trim()).then(() => {
        const orig = el.style.opacity;
        el.style.opacity = '.5';
        setTimeout(() => el.style.opacity = orig, 300);
      });
    });
  });
});
