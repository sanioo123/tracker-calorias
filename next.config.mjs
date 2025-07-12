/** @type {import('next').NextConfig} */
const nextConfig = {
  devIndicators: false,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=()'
          },
          ...(process.env.NODE_ENV === 'production' ? [{
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload'
          }] : [])
        ]
      },
      {
        source: '/api/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, no-cache, must-revalidate, proxy-revalidate'
          },
          {
            key: 'Pragma',
            value: 'no-cache'
          },
          {
            key: 'Expires',
            value: '0'
          }
        ]
      }
    ];
  },

  async rewrites() {
    return {
      beforeFiles: [
        {
          source: '/api/internal/:path*',
          destination: '/404'
        },
        {
          source: '/.env:path*',
          destination: '/404'
        },
        {
          source: '/config/:path*',
          destination: '/404'
        }
      ]
    };
  },

  poweredByHeader: false,
  
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn']
    } : false,
  },

  webpack: (config, { dev, isServer }) => {
    if (!dev) {
      config.optimization = {
        ...config.optimization,
        minimize: true,
        concatenateModules: true,
      };
      
      config.devtool = false;
    }

    config.resolve = {
      ...config.resolve,
      symlinks: false,
    };

    return config;
  },

  async redirects() {
    return [
      {
        source: '/.env',
        destination: '/404',
        permanent: true
      },
      {
        source: '/.env.local',
        destination: '/404',
        permanent: true
      },
      {
        source: '/.env.production',
        destination: '/404',
        permanent: true
      },
      {
        source: '/package.json',
        destination: '/404',
        permanent: true
      },
      {
        source: '/package-lock.json',
        destination: '/404',
        permanent: true
      }
    ];
  },

  experimental: {
    optimizeCss: true
  },

  serverExternalPackages: [
    'bcryptjs',
    'mysql2',
    'jsonwebtoken'
  ],

  images: {
    domains: [],
    loader: 'default',
    formats: ['image/webp', 'image/avif'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
  },

  trailingSlash: false,
  output: process.env.BUILD_STANDALONE === 'true' ? 'standalone' : undefined,
  ...(process.env.NODE_ENV === 'development' && {
    eslint: {
      ignoreDuringBuilds: false,
    },
    typescript: {
      ignoreBuildErrors: false,
    }
  }),

  ...(process.env.NODE_ENV === 'production' && {
    eslint: {
      ignoreDuringBuilds: false,
    },
    typescript: {
      ignoreBuildErrors: false,
    },
    swcMinify: true,
  })
};

export default nextConfig;