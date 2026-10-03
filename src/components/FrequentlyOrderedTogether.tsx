import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Users,
  Sparkles,
  ShoppingBag,
  Plus,
  Check,
  Flame,
  ArrowRight,
  Coffee,
  Cookie,
  Clock,
  TrendingUp,
  Tag,
} from 'lucide-react';
import {
  getAllFrequentlyOrderedBundles,
  findMatchingBundles,
  ResolvedFrequentlyOrderedBundle,
} from '../data/frequentlyOrderedData';
import { OfficialMenuItem } from '../data/officialMenuData';
import { CartItem } from '../types/coffee';
import { DietaryBadge } from './DietaryBadge';

interface FrequentlyOrderedTogetherProps {
  cart?: CartItem[];
  onAddToCart?: (item: OfficialMenuItem & { notes?: string; customPrice?: number }) => void;
  onOpenOrderModal?: () => void;
}

type FilterCategory = 'all' | 'signature' | 'breakfast' | 'evening';

export const FrequentlyOrderedTogether: React.FC<FrequentlyOrderedTogetherProps> = ({
  cart = [],
  onAddToCart,
  onOpenOrderModal,
}) => {
  const [filter, setFilter] = useState<FilterCategory>('all');
  const [addedItemIds, setAddedItemIds] = useState<Record<string, boolean>>({});
  const [addedBundleIds, setAddedBundleIds] = useState<Record<string, boolean>>({});

  // Extract set of product IDs currently in cart
  const cartItemIds = useMemo(() => {
    return cart.map((item) => item.id);
  }, [cart]);

  // Pre-calculate bundles sorted with cart matches first
  const bundles: ResolvedFrequentlyOrderedBundle[] = useMemo(() => {
    return findMatchingBundles(cartItemIds);
  }, [cartItemIds]);

  // Filtered bundles
  const filteredBundles = useMemo(() => {
    if (filter === 'all') return bundles;
    if (filter === 'signature') {
      return bundles.filter(
        (b) => b.id.includes('signature') || b.id.includes('pistachio'),
      );
    }
    if (filter === 'breakfast') {
      return bundles.filter(
        (b) => b.id.includes('morning') || b.id.includes('italian'),
      );
    }
    if (filter === 'evening') {
      return bundles.filter(
        (b) => b.id.includes('late-night') || b.id.includes('mojito'),
      );
    }
    return bundles;
  }, [bundles, filter]);

  // Identify if any bundle has a match in the cart
  const topCartMatchedBundle = useMemo(() => {
    if (cartItemIds.length === 0) return null;
    return bundles.find((b) => b.items.some((item) => cartItemIds.includes(item.id)));
  }, [bundles, cartItemIds]);

  const handleAddSingleItem = (item: OfficialMenuItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!onAddToCart) return;
    onAddToCart(item);
    setAddedItemIds((prev) => ({ ...prev, [item.id]: true }));
    window.setTimeout(() => {
      setAddedItemIds((prev) => {
        const next = { ...prev };
        delete next[item.id];
        return next;
      });
    }, 1500);
  };

  const handleAddFullBundle = (bundle: ResolvedFrequentlyOrderedBundle, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!onAddToCart) return;

    // Add all items in the bundle sequentially
    bundle.items.forEach((item, index) => {
      setTimeout(() => {
        onAddToCart(item);
      }, index * 120);
    });

    setAddedBundleIds((prev) => ({ ...prev, [bundle.id]: true }));
    window.setTimeout(() => {
      setAddedBundleIds((prev) => {
        const next = { ...prev };
        delete next[bundle.id];
        return next;
      });
    }, 1800);
  };

  const handleCompleteBundle = (bundle: ResolvedFrequentlyOrderedBundle, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!onAddToCart) return;

    // Add only the items from the bundle that aren't already in the cart
    const missingItems = bundle.items.filter((item) => !cartItemIds.includes(item.id));
    if (missingItems.length === 0) {
      // If all items are already in cart, add the whole bundle again
      handleAddFullBundle(bundle, e);
      return;
    }

    missingItems.forEach((item, index) => {
      setTimeout(() => {
        onAddToCart(item);
      }, index * 120);
    });

    setAddedBundleIds((prev) => ({ ...prev, [bundle.id]: true }));
    window.setTimeout(() => {
      setAddedBundleIds((prev) => {
        const next = { ...prev };
        delete next[bundle.id];
        return next;
      });
    }, 1800);
  };

  return (
    <section
      id="frequently-ordered-together"
      aria-labelledby="frequently-ordered-heading"
      className="scroll-mt-36 mb-16 sm:mb-24"
    >
      <div className="relative rounded-3xl p-6 sm:p-9 md:p-11 bg-gradient-to-br from-[#291016] via-[#351016] to-[#1e080d] text-[#faf6ee] border border-[#c9833a]/35 shadow-[0_24px_70px_-20px_rgba(33,10,15,0.7)] overflow-hidden">
        {/* Subtle Decorative Ambient Lighting */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#c9833a]/12 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-80 h-80 bg-[#f4d19b]/8 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 space-y-8">
          {/* 1. Header Row */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-6 border-b border-[#dfd4c5]/20">
            <div className="space-y-2 max-w-2xl">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#c9833a]/20 border border-[#c9833a]/40 text-[#f4d19b] text-[10.5px] font-sans font-bold uppercase tracking-[0.2em]">
                <Users className="w-3.5 h-3.5 text-[#f4d19b]" />
                <span>FREQUENTLY ORDERED TOGETHER</span>
              </div>

              <h3
                id="frequently-ordered-heading"
                className="font-serif font-bold text-2xl sm:text-3xl md:text-4xl text-white tracking-tight"
              >
                Guest Favorite Pairings & Bundles
              </h3>

              <p className="font-sans text-xs sm:text-sm text-[#e8dfd1]/85 leading-relaxed">
                Popular coffee and patisserie combinations frequently ordered together by Miliana café guests. Add any complete bundle to your tray with a single tap.
              </p>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-1">
              {[
                { id: 'all', label: 'All Combos' },
                { id: 'signature', label: 'Signatures' },
                { id: 'breakfast', label: 'Breakfast' },
                { id: 'evening', label: 'Evening' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFilter(tab.id as FilterCategory)}
                  className={`text-xs px-3.5 py-1.5 rounded-full font-medium tracking-wide transition-all cursor-pointer whitespace-nowrap ${
                    filter === tab.id
                      ? 'bg-[#c9833a] text-[#1b0d09] font-bold shadow-xs'
                      : 'bg-white/10 hover:bg-white/20 text-[#d8cbb8]'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* 2. Cart Matching Banner (Shown when customer already has one of the bundle items in cart) */}
          {topCartMatchedBundle && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-4 sm:p-4.5 rounded-2xl bg-gradient-to-r from-[#c9833a]/25 via-[#f4d19b]/15 to-[#c9833a]/25 border border-[#f4d19b]/40 backdrop-blur-md flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-inner"
            >
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-[#f4d19b] text-[#1b0d09] flex items-center justify-center shrink-0 font-bold shadow-xs">
                  <Sparkles className="w-4 h-4 text-[#1b0d09]" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase font-bold tracking-wider text-[#f4d19b]">
                      Matches an Item in Your Tray
                    </span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[#2e7d32]" />
                  </div>
                  <p className="font-sans text-xs sm:text-sm text-white font-medium">
                    Guests with items in their cart love completing{' '}
                    <strong className="text-[#f4d19b]">{topCartMatchedBundle.title}</strong>!
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={(e) => handleCompleteBundle(topCartMatchedBundle, e)}
                className="self-start sm:self-auto inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-[#f4d19b] to-[#c9833a] hover:brightness-110 text-[#1b0d09] text-xs font-bold uppercase tracking-wider transition-all shadow-sm cursor-pointer whitespace-nowrap active:scale-95"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Complete This Pair</span>
              </button>
            </motion.div>
          )}

          {/* 3. Grid of Frequently Ordered Together Bundles */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 sm:gap-6">
            {filteredBundles.map((bundle) => {
              const isBundleAdded = Boolean(addedBundleIds[bundle.id]);
              const itemsInCartCount = bundle.items.filter((item) =>
                cartItemIds.includes(item.id),
              ).length;
              const hasAllItems = itemsInCartCount === bundle.items.length;
              const hasSomeItems = itemsInCartCount > 0 && !hasAllItems;
              const missingItemsPrice = bundle.items
                .filter((item) => !cartItemIds.includes(item.id))
                .reduce((sum, item) => sum + item.priceNum, 0);

              return (
                <div
                  key={bundle.id}
                  className={`rounded-2xl p-5 sm:p-6 bg-white/[0.05] hover:bg-white/[0.08] border transition-all duration-300 flex flex-col justify-between relative overflow-hidden group ${
                    hasSomeItems
                      ? 'border-[#f4d19b]/60 shadow-[0_12px_32px_-8px_rgba(201,131,58,0.25)]'
                      : 'border-white/10 hover:border-[#c9833a]/50'
                  }`}
                >
                  <div className="space-y-4">
                    {/* Top Badges & Metric */}
                    <div className="flex items-start justify-between gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-[#c9833a]/25 text-[#f4d19b] border border-[#c9833a]/40 text-[10px] font-sans font-bold uppercase tracking-wider">
                        {bundle.badge}
                      </span>

                      <div className="flex items-center gap-1 text-[10px] font-sans text-[#d8cbb8]/80 bg-black/20 px-2 py-0.5 rounded-full">
                        <TrendingUp className="w-3 h-3 text-[#f4d19b]" />
                        <span>Popular Pair</span>
                      </div>
                    </div>

                    {/* Title & Tagline */}
                    <div>
                      <h4 className="font-serif font-bold text-lg sm:text-xl text-white group-hover:text-[#f4d19b] transition-colors">
                        {bundle.title}
                      </h4>
                      <p className="font-serif italic text-xs sm:text-sm text-[#f4d19b]/90 mt-0.5">
                        {bundle.tagline}
                      </p>
                    </div>

                    {/* Popularity Quote / Stat */}
                    <div className="flex items-center gap-1.5 text-xs text-[#d8cbb8] font-sans bg-black/30 px-3 py-2 rounded-xl border border-white/5">
                      <Users className="w-3.5 h-3.5 text-[#c9833a] shrink-0" />
                      <span className="truncate">{bundle.popularityMetric}</span>
                    </div>

                    {/* Items List inside Bundle */}
                    <div className="space-y-2 pt-1">
                      <span className="text-[10px] font-sans uppercase font-bold tracking-widest text-[#8a7a6f] block">
                        Included in this combo:
                      </span>

                      {bundle.items.map((item, idx) => {
                        const isThisItemInCart = cartItemIds.includes(item.id);
                        const isRecentlyAdded = addedItemIds[item.id];

                        return (
                          <div
                            key={item.id}
                            className={`p-2.5 rounded-xl border transition-all flex items-center justify-between gap-2 text-xs ${
                              isThisItemInCart
                                ? 'bg-[#2e7d32]/15 border-[#2e7d32]/40 text-white'
                                : 'bg-white/5 border-white/10 hover:border-white/20 text-[#faf6ee]'
                            }`}
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="w-5 h-5 rounded-md bg-white/10 text-[#f4d19b] flex items-center justify-center shrink-0 text-[10px] font-mono">
                                {idx + 1}
                              </span>
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="font-medium text-white truncate">
                                    {item.name}
                                  </span>
                                  {item.dietary && item.dietary.length > 0 && (
                                    <span className="inline-flex items-center gap-1">
                                      {item.dietary.map((tag) => (
                                        <DietaryBadge
                                          key={tag}
                                          tag={tag}
                                          theme="dark"
                                          size="xs"
                                        />
                                      ))}
                                    </span>
                                  )}
                                </div>
                                <span className="text-[10px] text-[#d8cbb8]/70 capitalize block">
                                  {item.category}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span className="font-mono font-bold text-xs text-[#f4d19b]">
                                {item.price}
                              </span>

                              {isThisItemInCart ? (
                                <span className="inline-flex items-center gap-1 text-[10px] text-[#81c784] font-semibold bg-[#2e7d32]/30 px-2 py-0.5 rounded">
                                  <Check className="w-2.5 h-2.5" />
                                  <span>In tray</span>
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  onClick={(e) => handleAddSingleItem(item, e)}
                                  className={`p-1 rounded-md text-[10px] transition-colors cursor-pointer ${
                                    isRecentlyAdded
                                      ? 'bg-[#2e7d32] text-white'
                                      : 'bg-white/10 hover:bg-[#c9833a] hover:text-white text-[#d8cbb8]'
                                  }`}
                                  aria-label={`Add single item ${item.name} to tray`}
                                >
                                  {isRecentlyAdded ? (
                                    <Check className="w-3 h-3" />
                                  ) : (
                                    <Plus className="w-3 h-3" />
                                  )}
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Bottom Price & CTA */}
                  <div className="pt-4 mt-4 border-t border-white/10 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <span className="text-[10px] font-sans uppercase tracking-widest text-[#8a7a6f] block">
                          Bundle Total
                        </span>
                        <span className="font-mono text-lg font-bold text-white">
                          {bundle.formattedPrice}
                        </span>
                      </div>

                      {bundle.perkText && (
                        <span className="text-[10.5px] font-sans text-[#f4d19b] text-right font-medium max-w-[150px] leading-tight">
                          {bundle.perkText}
                        </span>
                      )}
                    </div>

                    {/* Primary Button: Add Bundle or Complete Pair */}
                    <button
                      type="button"
                      onClick={(e) =>
                        hasSomeItems
                          ? handleCompleteBundle(bundle, e)
                          : handleAddFullBundle(bundle, e)
                      }
                      className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-sm cursor-pointer active:scale-98 ${
                        isBundleAdded
                          ? 'bg-[#2e7d32] text-white'
                          : hasSomeItems
                          ? 'bg-gradient-to-r from-[#f4d19b] to-[#c9833a] hover:brightness-110 text-[#1b0d09]'
                          : hasAllItems
                          ? 'bg-white/15 hover:bg-white/25 text-white border border-white/20'
                          : 'bg-gradient-to-r from-[#c9833a] via-[#df9e59] to-[#c9833a] hover:brightness-110 text-[#1b0d09]'
                      }`}
                    >
                      {isBundleAdded ? (
                        <>
                          <Check className="w-4 h-4" />
                          <span>Bundle Added to Tray!</span>
                        </>
                      ) : hasSomeItems ? (
                        <>
                          <Plus className="w-4 h-4" />
                          <span>Complete Pair (+{missingItemsPrice} DA)</span>
                        </>
                      ) : hasAllItems ? (
                        <>
                          <Check className="w-4 h-4 text-[#81c784]" />
                          <span>Add Another Bundle (+{bundle.totalPriceNum} DA)</span>
                        </>
                      ) : (
                        <>
                          <ShoppingBag className="w-4 h-4" />
                          <span>Add Bundle to Tray</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
};
