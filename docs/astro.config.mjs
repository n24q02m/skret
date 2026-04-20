import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://skret.n24q02m.com',
  integrations: [
    starlight({
      title: 'skret',
      description: 'Cloud-provider secret manager CLI with Doppler/Infisical-grade DX',
      logo: {
        light: './src/assets/logo.svg',
        dark: './src/assets/logo-dark.svg',
        alt: 'skret logo',
        replacesTitle: false,
      },
      favicon: '/favicon.svg',
      head: [
        { tag: 'link', attrs: { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://skret.n24q02m.com/og-image.png' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: 'https://skret.n24q02m.com/og-image.png' } },
      ],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/n24q02m/skret' },
      ],
      editLink: {
        baseUrl: 'https://github.com/n24q02m/skret/edit/main/docs/',
      },
      sidebar: [
        { label: 'Guide', autogenerate: { directory: 'guide' } },
        { label: 'Providers', autogenerate: { directory: 'providers' } },
        { label: 'Migration', autogenerate: { directory: 'migration' } },
        { label: 'Integrations', autogenerate: { directory: 'integrations' } },
        { label: 'Reference', autogenerate: { directory: 'reference' } },
        { label: 'Contributing', autogenerate: { directory: 'contributing' } },
        { label: 'FAQ', link: '/faq/' },
      ],
    }),
    sitemap(),
  ],
});
