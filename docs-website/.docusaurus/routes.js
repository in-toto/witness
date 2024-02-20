import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/__docusaurus/debug',
    component: ComponentCreator('/__docusaurus/debug', '154'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/config',
    component: ComponentCreator('/__docusaurus/debug/config', '8e2'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/content',
    component: ComponentCreator('/__docusaurus/debug/content', '2da'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/globalData',
    component: ComponentCreator('/__docusaurus/debug/globalData', '3ab'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/metadata',
    component: ComponentCreator('/__docusaurus/debug/metadata', '67e'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/registry',
    component: ComponentCreator('/__docusaurus/debug/registry', '72d'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/routes',
    component: ComponentCreator('/__docusaurus/debug/routes', '589'),
    exact: true
  },
  {
    path: '/docs',
    component: ComponentCreator('/docs', '3d8'),
    routes: [
      {
        path: '/docs',
        component: ComponentCreator('/docs', 'c9e'),
        routes: [
          {
            path: '/docs',
            component: ComponentCreator('/docs', 'd14'),
            routes: [
              {
                path: '/docs/',
                component: ComponentCreator('/docs/', 'b31'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/CODE_OF_CONDUCT',
                component: ComponentCreator('/docs/CODE_OF_CONDUCT', 'e8d'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/CONTRIBUTING',
                component: ComponentCreator('/docs/CONTRIBUTING', '6d0'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/about/how-witness-works',
                component: ComponentCreator('/docs/docs/about/how-witness-works', '32f'),
                exact: true
              },
              {
                path: '/docs/docs/attestors/aws-iid',
                component: ComponentCreator('/docs/docs/attestors/aws-iid', 'd98'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/commandrun',
                component: ComponentCreator('/docs/docs/attestors/commandrun', 'b30'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/environment',
                component: ComponentCreator('/docs/docs/attestors/environment', 'b27'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/gcp-iit',
                component: ComponentCreator('/docs/docs/attestors/gcp-iit', '3b9'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/git',
                component: ComponentCreator('/docs/docs/attestors/git', '323'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/gitlab',
                component: ComponentCreator('/docs/docs/attestors/gitlab', '667'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/jwt',
                component: ComponentCreator('/docs/docs/attestors/jwt', '04a'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/material',
                component: ComponentCreator('/docs/docs/attestors/material', '63a'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/maven',
                component: ComponentCreator('/docs/docs/attestors/maven', '028'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/oci',
                component: ComponentCreator('/docs/docs/attestors/oci', 'daa'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/attestors/product',
                component: ComponentCreator('/docs/docs/attestors/product', '860'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/commands',
                component: ComponentCreator('/docs/docs/commands', 'dc1'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/concepts/attestor',
                component: ComponentCreator('/docs/docs/concepts/attestor', 'e45'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/concepts/config',
                component: ComponentCreator('/docs/docs/concepts/config', '102'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/concepts/policy',
                component: ComponentCreator('/docs/docs/concepts/policy', '4af'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/signers/kms',
                component: ComponentCreator('/docs/docs/signers/kms', '656'),
                exact: true
              },
              {
                path: '/docs/docs/tutorials/artifact-policy',
                component: ComponentCreator('/docs/docs/tutorials/artifact-policy', '5d1'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/tutorials/getting-started',
                component: ComponentCreator('/docs/docs/tutorials/getting-started', '6a0'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/docs/docs/tutorials/sigstore-keyless',
                component: ComponentCreator('/docs/docs/tutorials/sigstore-keyless', '879'),
                exact: true,
                sidebar: "docsSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '/',
    component: ComponentCreator('/', 'e2c'),
    exact: true
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];
