import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Attest and Verify',
    Svg: require('@site/static/img/undraw_certificate_re_yadi.svg').default,
    description: (
      <>
        Create in-toto attestations for your software supply chains, so you can verify
        who did what and what tools were used.
      </>
    ),
  },
  {
    title: 'Prevent Attacks',
    Svg: require('@site/static/img/undraw_alert_re_j2op.svg').default,
    description: (
      <>
        Detect any potential tampering or malicious activity.
      </>
    ),
  },
  {
    title: 'Create Trust Based Supply Chains',
    Svg: require('@site/static/img/undraw_programmer_re_owql.svg').default,
    description: (
      <>
        Ensure that only authorized users or machines complete each step of the supply chain.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
