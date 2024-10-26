import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Kyanos",
  description: "Kyanos official website",
  head: [["link", { rel: "icon", href: "/kyanos.png" }]], // 浏览器标签页logo
  locales: {
    cn: { label: '简体中文', lang: 'cn' },
    root: { label: 'English', lang: 'en' },
  },
  appearance: 'dark',
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: "/kyanos.png",
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: './what-is-kyanos' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is Kyanos?', link: './what-is-kyanos' },
          { text: 'Quickstart', link: './quickstart' },
        ]
      },
      {
        text: 'Tutorial',
        items: [
          
          { text: 'Learn kyanos in 5 minutes', link: './how-to' },
          { text: 'How to use watch', link: './watch' },
          { text: 'How to use stat', link: './stat' },
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/hengyoush/kyanos' }
    ],
    
    footer: {
      message: 'Released under the <a href="https://github.com/hengyoush/kyanos/blob/main/LICENSE">Apache-2.0 license.',
      copyright: 'Copyright © 2024-present <a href="https://github.com/hengyoush">Hengyoush'
    },
    
    search: {
      provider: 'local'
    },
  }
})
