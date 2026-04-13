import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'skret',
  description: 'Cloud-provider secret manager CLI wrapper',
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Reference', link: '/reference/error-codes' },
      { text: 'Providers', link: '/providers/aws' },
      { text: 'FAQ', link: '/faq' },
      { text: 'GitHub', link: 'https://github.com/n24q02m/skret' }
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Authentication', link: '/guide/authentication' },
          { text: 'Troubleshooting', link: '/guide/troubleshooting' }
        ]
      },
      {
        text: 'Providers',
        items: [
          { text: 'Comparison & Ranking', link: '/providers/comparison' },
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
      },
      {
        text: 'Integrations',
        items: [
          { text: 'GitHub Actions', link: '/integrations/github-actions' },
          { text: 'Makefile Patterns', link: '/integrations/makefile-patterns' },
          { text: 'Docker Compose', link: '/integrations/docker-compose' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Error Codes', link: '/reference/error-codes' },
          { text: 'Config Schema', link: '/reference/config-schema' },
          { text: 'Library API', link: '/reference/library-api' }
        ]
      },
      {
        text: 'Contributing',
        items: [
          { text: 'Dev Setup', link: '/contributing/setup' },
          { text: 'Adding a Provider', link: '/contributing/adding-provider' },
          { text: 'Release Process', link: '/contributing/release-process' }
        ]
      },
      {
        text: 'FAQ',
        link: '/faq'
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/n24q02m/skret' }
    ]
  }
})
