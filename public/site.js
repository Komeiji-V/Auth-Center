// 站点设置注入：标题/图标/背景（所有页面引入，无主题切换）
(function () {
  fetch('/api/config')
    .then((r) => r.json())
    .then((d) => {
      const site = d.site || {};
      window.SITE = site;
      if (site.site_title) document.title = site.site_title;
      if (site.site_icon) {
        let link = document.querySelector('link[rel="icon"]');
        if (!link) {
          link = document.createElement('link');
          link.rel = 'icon';
          document.head.appendChild(link);
        }
        link.href = site.site_icon;
      }
      if (site.site_bg) {
        const esc = String(site.site_bg).replace(/"/g, '\\"');
        document.documentElement.style.setProperty('--site-bg', 'url("' + esc + '")');
      }
    })
    .catch(() => {});
})();
