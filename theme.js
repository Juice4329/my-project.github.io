// ===== Переменные для управления темой =====
const themeToggle = document.getElementById('themeToggle'); // Кнопка переключения темы
const darkIcon = document.getElementById('darkIcon');       // Иконка "тёмная тема"
const lightIcon = document.getElementById('lightIcon');     // Иконка "светлая тема"
const html = document.documentElement;                      // Корневой HTML-элемент

// ===== Инициализация темы при загрузке страницы =====
function initTheme() {
  const savedTheme = localStorage.getItem('theme') ||
                     (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  html.classList.toggle('dark', savedTheme === 'dark'); // Применяем тему
  updateIcons(); // Обновляем иконки
}

// ===== Обновление отображения иконок темы =====
function updateIcons() {
  if (!darkIcon || !lightIcon) return;
  if (html.classList.contains('dark')) {
    darkIcon.classList.add('hidden');     // Скрываем иконку тёмной темы
    lightIcon.classList.remove('hidden'); // Показываем иконку светлой темы
  } else {
    darkIcon.classList.remove('hidden');  // Показываем иконку тёмной темы
    lightIcon.classList.add('hidden');    // Скрываем иконку светлой темы
  }
}

// ===== Переключение темы по клику на кнопку =====
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const isDark = html.classList.toggle('dark'); // Переключаем класс 'dark'
    localStorage.setItem('theme', isDark ? 'dark' : 'light'); // Сохраняем выбор
    updateIcons(); // Обновляем иконки
  });
}

// ===== Запуск инициализации темы =====
initTheme();

// ===== Обработка событий после полной загрузки документа =====
document.addEventListener("DOMContentLoaded", function () {
  const navLinks = document.querySelectorAll(".nav-item"); // Навигационные ссылки
  if (!navLinks.length) return;

  // Плавный скролл при клике по ссылке
  navLinks.forEach(link => {
    link.addEventListener("click", function (e) {
      e.preventDefault();
      const targetId = this.getAttribute("href");
      const targetSection = document.querySelector(targetId);
      if (targetSection) {
        targetSection.scrollIntoView({ behavior: "smooth" });
      }
    });
  });

  // Используем Intersection Observer для обновления активной ссылки без лагов
  const observerOptions = {
    root: null,
    rootMargin: '-50% 0px -50% 0px', // Отслеживаем появление секции в центре экрана
    threshold: 0
  };

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      const id = '#' + entry.target.id;
      const navLink = document.querySelector(`.nav-item[href="${id}"]`);
      if (!navLink) return;

      if (entry.isIntersecting) {
        // Сбрасываем классы у всех ссылок
        navLinks.forEach(link => {
          link.classList.remove("active", "text-blue-600", "dark:text-blue-400");
          link.classList.add("text-gray-500", "dark:text-gray-300");
        });
        // Добавляем активный класс для текущей ссылки
        navLink.classList.add("active", "text-blue-600", "dark:text-blue-400");
      }
    });
  }, observerOptions);

  // Наблюдаем все секции по id из ссылок
  navLinks.forEach(link => {
    const sectionId = link.getAttribute("href");
    const section = document.querySelector(sectionId);
    if (section) {
      observer.observe(section);
    }
  });
});
