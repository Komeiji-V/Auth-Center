// 站点设置注入：标题/图标（背景由 login 页取色代码统一处理，避免双重加载换图）
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
    })
    .catch(() => {});
})();
