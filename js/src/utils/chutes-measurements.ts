import type { ChutesMeasurementBaseline } from '../types/attestation-chutes';

/**
 * Fixed snapshot of the Gateway's 29 vetted VM baselines (not fetched at runtime).
 * Source: https://github.com/nearai/cloud-api/blob/a9df6f2cc63d567a011641eb9bbaf393c0ef81aa/crates/services/src/attestation/chutes.rs#L208-L370
 * These identify the VM platform, not the model weights or inference workload.
 * Updating them is a trust-policy change and requires reviewing the full register
 * tuple. Rows from different versions must never be mixed.
 */
const FAMILIES = [
  {
    version: '1.3.0',
    mrTd: 'ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455',
    rtMr1:
      'f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877',
    rtMr2:
      '7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c',
    rtMr3:
      'bfac8bbe97148d00c0bc5dea273ccd926e2415511f08f5dedaa96d3c19e824d2bf01fae86e8987ff509fd3ad31374a60',
    hardware: [
      [
        '8xh200',
        '2864b11878e8129095d62a5dd7c3e3aae178d3a077606a825617324768f189ad05aed08376947df92d6c75865d915cbf',
      ],
      [
        '8xh200-r2',
        'c0466500b034f7b51be7ea0fcc477e60b54833d927db96e4826ac37c60ec02dc28703a16af551f46be17035157b474da',
      ],
      [
        '8xRTX_PRO_6000',
        '5064826bfd530ca9f823ceecb74899d7dbd014b60897a77317a14200c8706f2368ecbbc0a04cec8ceef90474b8c955e1',
      ],
      [
        '8xb200',
        '734628b9a715ec492c2b14b409907f32d91847f439ba8bac2fa985b41c01245536348fefb2e021ed574c290c8c50347a',
      ],
      [
        '8xb200-eth',
        '724c1d0d20c11a479d2874fa543b0f1b920be32f2a5b9707fa5bcf6176fff31aeac9436e541e1125f78a0b61f7c2e165',
      ],
      [
        '8xb300',
        '31f6446add906b7d56132c600549270a8ea780193e0c89586f784b20b25136de441ca715d5ecf86ae72f0b40f7a47f39',
      ],
    ],
  },
  {
    version: '1.3.1-rc1',
    mrTd: '261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d',
    rtMr1:
      '8cfb5e5a387eef8b5fb7be77ab4405d4b68990d20990e6eec0551c5b682ee7d9fcf7fad7bd6e07b373b2e23321c98a5f',
    rtMr2:
      '2de048a63a3f1ae6bf0f9631bbfa5ffc703392211e2e71dd5fcf645187ee6c4b404883fbbadfcdce294274d9f4ae70ce',
    rtMr3:
      '5b6a2b127a80e4aa71dae6dfa2f1f813e1c1606fdf4ee0947010d29f582813a0860e919860e25febfeb60125988cb9bb',
    hardware: [
      [
        '8xb200',
        '7c028a01902475caaa81c245151184d08fcb847cfcbac4ced3c6812d2abe101680d5c015e7cfdb1c98ae54ae7ff0d524',
      ],
      [
        '8xb200-xeon6',
        '2b22fa53ace208d4f046ae90b7ad28d71a7f4ef0573897d40f6c82b4036217e3170c856f91e54bc19c20c9958c5d1e36',
      ],
      [
        '8xb300',
        '43204fcb166114bee9ea562d88fef18d618f591499f8b73ac87be07962f2b228569b680d2ede4ed719d4a3514f90feda',
      ],
    ],
  },
  {
    version: '1.3.1',
    mrTd: '261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d',
    rtMr1:
      '9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207',
    rtMr2:
      '8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968',
    rtMr3:
      '51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433',
    hardware: [
      [
        '8xh200 [10.2.1]',
        '212d8284fe29a52a033cd662763e452915d2002bcc3c3e73aa660b100087bd3cce8aef414c3d7012f6a857f392c1919b',
      ],
      [
        '8xh200 [10.2.1, NVSW0]',
        'c90a27d633d97e2f785a0a65c4a7ee2258872655e3bada2cad0e719e313db542fd35c6889897d9ae6369f82e39877861',
      ],
      [
        '8xh200 [10.1.0]',
        '7e76988fae31dda82f0043b331d908f0716e9da24fed80b6ea6cec9b6615ff84f24321056a8befbea3fff67bd1e59205',
      ],
      [
        '8xh200 [10.1.0, NVSW0]',
        'cdf7169a9f90c4d2fd29f89579f4ad7b90c272d607bc7ba2365e91560a248b9eafe01940f3c1e9d6bd6987573080b6c1',
      ],
      [
        '8xh200 [10.1.0-flat]',
        'ed373dfcc4e3b9cc57282773784c88445699f95705ec0995959c4aa95f9dec454c76da891fa56f820f547b02db8c1f2f',
      ],
      [
        '8xRTX_PRO_6000',
        '0917443cc41e9a5afebc8e87e69a63f32208c47d4b4b4fd410fbc1a705e1880c1383a4ad51903a5ed20cb4090420185a',
      ],
      [
        '8xb200 [10.2.1]',
        '35038cbb04f872ac6d2784b05c912c438007583e58960dc66fb02d1b04462dd5994f94536da37b5877ccd3dd27d8d54d',
      ],
      [
        '8xb200 [10.2.1, IB4]',
        '555fc635cd49723dc33d53a9d53be82fd161be351174e5449a465bbeffbcbd01f36d89dcd25fad61bf4c9e65c570f5d6',
      ],
      [
        '8xb200 [10.2.1, XEON6]',
        '65fd972e40ac4d8a933d10ebfc31f07336cf1e45a3864523427b454df5d3b9dd0043f10e975da39677b62d45860c13e3',
      ],
      [
        '8xb200 [10.1.0, XEON6, SNC3]',
        '2b22fa53ace208d4f046ae90b7ad28d71a7f4ef0573897d40f6c82b4036217e3170c856f91e54bc19c20c9958c5d1e36',
      ],
      [
        '8xb300',
        '91adf9667ba4c65bec5345a8c9b98010708d903847bf838c4526c3ebbc35561719e2127e48a3f6f77f651d71d2cbc8d4',
      ],
      [
        '8xh200 [10.2.1, FLAT]',
        'b237753a1c8a05042209947fc0f98c8459783db7f3411860c38249c5abd4efd8c6fb7820036ff19b5099138aaf9e0bd1',
      ],
      [
        '8xRTX_PRO_6000 [10.1.0]',
        '0917443cc41e9a5afebc8e87e69a63f32208c47d4b4b4fd410fbc1a705e1880c1383a4ad51903a5ed20cb4090420185a',
      ],
      [
        '8xRTX_PRO_6000 [10.2.1, NUMA2-4/4]',
        '5fc09d108ef74d5505b876690de5ab5da02af463ba84bb33299efd1c02144b5d7a6ba579b3ff31ef9118350468e9faf2',
      ],
      [
        '8xRTX_PRO_6000 [10.2.1, NUMA2-3/5]',
        '1de32a41a8116e042f33e9cb813f1f6edfef1452c8b2cf54df5451a848ef8931e97f40927191acabfd111c8b8d66796a',
      ],
      [
        '8xRTX_PRO_6000 [10.2.1, FLAT]',
        'e9f0b31ce30e4917767d22ad26ad0a8f4edc095b8d9f4bbb36c9cc24fe274aa2dfe16ce3c961dac2d8cef3e6ae2e901d',
      ],
      [
        '8xRTX_PRO_6000 [10.2.1, FLAT, MSI-GNR]',
        '872d965083f0bab7d080bd7d40155ba1b2b911d883f391ab7d6b9d810abeefd058e04129d72c088cf4fd05c099a57704',
      ],
      [
        '8xb200 [10.2.1, XEON6, 272CPU]',
        '9673907ceb0c9ca79337437bb91695e7a3d19e82df1e41de1b0d2db8081fccb5d82f26d479a5016553cb20964d5948b9',
      ],
      [
        '8xb200 [10.2.1, XEON6, SNC3]',
        'ccef43242ef633a542405dbfe55d04d823a50586b0a07510d058ea88ad8d1f8281f227f00c664435d92b23431c4d1c3c',
      ],
      [
        '8xb200 [10.2.1, ubuntu3]',
        'ff42d0f7b03cbe84f9e252d8f912b465852c8ee92584c5c047de134a46c8f1e1545683e713bbdd64e2af7d10e8bafaae',
      ],
    ],
  },
] as const;

export const CHUTES_MEASUREMENT_BASELINES: readonly ChutesMeasurementBaseline[] =
  Object.freeze(
    FAMILIES.flatMap(({ hardware, ...software }) =>
      hardware.map(([name, rtMr0]) =>
        Object.freeze({ name, rtMr0, ...software }),
      ),
    ),
  );
