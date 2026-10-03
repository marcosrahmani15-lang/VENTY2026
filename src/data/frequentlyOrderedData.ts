import { OfficialMenuItem, getOfficialProductById, getAllOfficialProducts } from './officialMenuData';

export interface FrequentlyOrderedBundleConfig {
  id: string;
  title: string;
  tagline: string;
  badge: string;
  description: string;
  popularityMetric: string;
  itemIds: string[];
  perkText?: string;
  savingsText?: string;
  popularTime?: string;
}

export const FREQUENTLY_ORDERED_CONFIGS: FrequentlyOrderedBundleConfig[] = [
  {
    id: 'bundle-miliana-signature',
    title: 'The Signature Miliana Pairing',
    tagline: 'Spanish Latte & Basque Burnt Cheesecake',
    badge: 'Guest Choice #1',
    description: 'Our most celebrated pairing: spiced sweet condensed milk double espresso balanced by caramelized scorched cheesecake.',
    popularityMetric: 'Ordered together by 86% of afternoon visitors',
    itemIds: ['latte-spanish-latte', 'dessert-banque-burnt-cheesecake'],
    perkText: '+2 Bonus Loyalty Stamps with this pairing',
    popularTime: 'Daily 17:00 – 21:00',
  },
  {
    id: 'bundle-morning-terrace',
    title: 'Morning Terrace Breakfast',
    tagline: 'Artisan Cappuccino & French Butter Croissant',
    badge: 'Breakfast Favorite',
    description: 'The golden morning ritual: flaky 72-layer laminated pure butter viennoiserie dipped into thick cocoa-dusted micro-foam.',
    popularityMetric: '74% of morning guests pair these two',
    itemIds: ['latte-cappuccino', 'style-croissant'],
    perkText: 'Served warm with pure butter viennoiserie',
    popularTime: 'Morning & Early Afternoon',
  },
  {
    id: 'bundle-italian-connoisseur',
    title: 'The Italian Connoisseur',
    tagline: 'Doppio Espresso & Traditional Tiramisu',
    badge: 'Barista Pick',
    description: 'Bold double extraction cacao notes that cut cleanly through hand-whipped Italian mascarpone and coffee-soaked savoiardi.',
    popularityMetric: 'Ordered 142 times this week',
    itemIds: ['coffee-doppio', 'dessert-tiramisu'],
    perkText: 'Double extraction & whipped mascarpone',
    popularTime: 'All-Day Energy',
  },
  {
    id: 'bundle-pistachio-dream',
    title: 'The Sicilian Pistachio Duo',
    tagline: 'Velvety Flat White & Pistachio Cheesecake',
    badge: 'Trending in Miliana',
    description: 'Thin, glossy micro-foam and roasted espresso crema harmonize with the crushed biscuit and Sicilian pistachio cream cheese.',
    popularityMetric: 'Ordered 98 times this month',
    itemIds: ['latte-flat-white', 'cheesecake-pistachio'],
    perkText: 'Toasted pistachios & velvety micro-foam',
    popularTime: 'Afternoon Pick-Me-Up',
  },
  {
    id: 'bundle-late-night-craving',
    title: 'Late Night Chocolate Indulgence',
    tagline: 'Chilled Cold Brew & Warm Molten Chocolate',
    badge: 'Late Night Craving',
    description: 'Sensory contrast: 16-hr steeped cold brew with dark cacao notes cleanses the palate between rich bites of warm molten lava cake.',
    popularityMetric: 'Top combination ordered 21:00 – 01:00',
    itemIds: ['coffee-cold-brew', 'dessert-fondant-chocolat'],
    perkText: 'Temperature contrast & molten ganache',
    popularTime: 'Evening 21:00 – 01:00',
  },
  {
    id: 'bundle-mojito-crepe',
    title: 'Afternoon Refresh & Crêpe',
    tagline: 'Classic Mojito & Chocolatée Crêpe',
    badge: 'Terrace Favorite',
    description: 'Effervescent crushed lime and garden mint pairs delightfully with freshly spun golden crêpes folded with melted Belgian chocolate.',
    popularityMetric: 'Guest favorite on warm Miliana afternoons',
    itemIds: ['mojito-classic', 'crepe-chocolatee'],
    perkText: 'Crisp mint citrus & warm chocolate ribbons',
    popularTime: 'Warm Afternoons',
  },
];

export interface ResolvedFrequentlyOrderedBundle {
  id: string;
  title: string;
  tagline: string;
  badge: string;
  description: string;
  popularityMetric: string;
  perkText?: string;
  savingsText?: string;
  popularTime?: string;
  items: OfficialMenuItem[];
  totalPriceNum: number;
  formattedPrice: string;
}

export function resolveBundle(config: FrequentlyOrderedBundleConfig): ResolvedFrequentlyOrderedBundle {
  const allProducts = getAllOfficialProducts();
  const items = config.itemIds
    .map((id) => allProducts.find((p) => p.id === id))
    .filter((p): p is OfficialMenuItem => Boolean(p));

  const totalPriceNum = items.reduce((sum, item) => sum + item.priceNum, 0);

  return {
    id: config.id,
    title: config.title,
    tagline: config.tagline,
    badge: config.badge,
    description: config.description,
    popularityMetric: config.popularityMetric,
    perkText: config.perkText,
    savingsText: config.savingsText,
    popularTime: config.popularTime,
    items,
    totalPriceNum,
    formattedPrice: `${totalPriceNum} DA`,
  };
}

export function getAllFrequentlyOrderedBundles(): ResolvedFrequentlyOrderedBundle[] {
  return FREQUENTLY_ORDERED_CONFIGS.map(resolveBundle);
}

// Find bundles matching any items currently in the cart
export function findMatchingBundles(cartItemIds: string[]): ResolvedFrequentlyOrderedBundle[] {
  const all = getAllFrequentlyOrderedBundles();
  if (!cartItemIds || cartItemIds.length === 0) {
    return all;
  }
  // Sort so bundles containing items in cart appear first
  return [...all].sort((a, b) => {
    const aMatch = a.items.some((item) => cartItemIds.includes(item.id));
    const bMatch = b.items.some((item) => cartItemIds.includes(item.id));
    if (aMatch && !bMatch) return -1;
    if (!aMatch && bMatch) return 1;
    return 0;
  });
}
