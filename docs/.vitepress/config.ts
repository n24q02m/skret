import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'skret',
  description: 'Cloud-provider secret manager CLI wrapper',
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/commands/init' },
      { text: 'Providers', link: '/providers/aws' },
      { text: 'GitHub', link: 'https://github.com/n24q02m/skret' }
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Configuration', link: '/guide/configuration' }
        ]
      },
      {
        text: 'Providers',
        items: [
          { text: 'AWS SSM', link: '/providers/aws' },
          { text: 'Local YAML', link: '/providers/local' }
        ]
      },
      {
        text: 'Migration',
        items: [
          { text: 'From Doppler', link: '/migration/from-doppler' },
          { text: 'From Infisical', link: '/migration/from-infisical' },
          { text: 'From dotenv', link: '/migration/from-dotenv' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/n24q02m/skret' }
    ]
  }
})
