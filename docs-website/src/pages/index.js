import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';

import Heading from '@theme/Heading';
import styles from './index.module.css';

import React from 'react';
import ReactDOM from 'react-dom';
import Snowfall from 'react-snowfall';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <>
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className={styles.heroTitle}>
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/docs/tutorials/getting-started"
            style={{color: 'black' }}>
            Try the Witness Getting Started Tutorial! 🦉
          </Link>
        </div>

      </div>
    </header>
    </>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`Welcome to the Witness Project!`}
      description="Generate in-toto attestations anywhere in your supply chain with Witness">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
