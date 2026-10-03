import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Sparkles,
  Coffee,
  Cookie,
  Plus,
  Check,
  ChevronDown,
  ChevronUp,
  Tag,
  Flame,
  ArrowRight,
} from 'lucide-react';
import {
  DailySpecial,
  ResolvedDailySpecial,
  getCurrentDailySpecial,
} from '../data/dailySpecialsData';
import { OfficialMenuItem, getOfficialProductById } from '../data/officialMenuData';
import { DietaryBadge } from './DietaryBadge';

interface DailySpecialsMarqueeProps {
  onAddToCart?: (item: OfficialMenuItem & { notes?: string; customPrice?: number }) => void;
  onOpenOrderModal?: () => void;
  onSelectCategory?: (category: string) => void;
}

export const DailySpecialsMarquee: React.FC<DailySpecialsMarqueeProps> = ({
  onAddToCart,
  onOpenOrderModal,
}) => {
  const [dailyData, setDailyData] = useState<ResolvedDailySpecial>(() => getCurrentDailySpecial());
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [addedIds, setAddedIds] = useState<Record<string, boolean>>({});
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Fetch from /api/menu/daily-specials with local fallback
  useEffect(() => {
    let isMounted = true;
    async function fetchDailySpecials() {
      try {
        const res = await fetch('/api/menu/daily-specials');
        if (res.ok) {
          const data = await res.json();
          if (data && data.special && isMounted) {
            const coffeeProduct = getOfficialProductById(data.special.coffeeItemId);
            const sweetProduct = getOfficialProductById(data.special.sweetItemId);
            setDailyData({
              special: data.special,
              coffeeProduct,
              sweetProduct,
            });
          }
        }
      } catch (err) {
        // Fallback already initialized synchronously
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    fetchDailySpecials();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleQuickAdd = (
    item: OfficialMenuItem | undefined,
    fallbackName: string,
    fallbackPriceNum: number,
    category: 'coffee' | 'sweets' | 'desserts',
    e?: React.MouseEvent,
  ) => {
    if (e) {
      e.stopPropagation();
    }
    const resolvedItem: OfficialMenuItem = item || {
      id: `daily-special-${category}`,
      name: fallbackName,
      price: `${fallbackPriceNum} DA`,
      priceNum: fallbackPriceNum,
      category: category === 'sweets' ? 'sweets' : category,
      subCategory: 'DAILY SPECIAL',
      currency: 'DA',
      available: true,
    };

    if (onAddToCart) {
      onAddToCart(resolvedItem);
      const itemId = resolvedItem.id;
      setAddedIds((prev) => ({ ...prev, [itemId]: true }));
      window.setTimeout(() => {
        setAddedIds((prev) => {
          const next = { ...prev };
          delete next[itemId];
          return next;
        });
      }, 1500);
    }
  };

  const handleAddBoth = () => {
    const { special, coffeeProduct, sweetProduct } = dailyData;
    handleQuickAdd(
      coffeeProduct,
      special.coffeeHighlight.title,
      coffeeProduct ? coffeeProduct.priceNum : 250,
      'coffee',
    );
    setTimeout(() => {
      handleQuickAdd(
        sweetProduct,
        special.sweetHighlight.title,
        sweetProduct ? sweetProduct.priceNum : 350,
        'sweets',
      );
    }, 180);
  };

  const { special, coffeeProduct, sweetProduct } = dailyData;
  const isCoffeeRecentlyAdded = coffeeProduct && addedIds[coffeeProduct.id];
  const isSweetRecentlyAdded = sweetProduct && addedIds[sweetProduct.id];

  // Marquee text ticker sequence
  const tickerItems = [
    { type: 'badge', text: special.badgeText },
    {
      type: 'coffee',
      label: 'Featured Coffee:',
      name: special.coffeeHighlight.title,
      price: special.coffeeHighlight.specialPrice,
      notes: special.coffeeHighlight.tastingNotes,
    },
    { type: 'separator', text: '✦' },
    {
      type: 'sweet',
      label: 'Featured Sweet:',
      name: special.sweetHighlight.title,
      price: special.sweetHighlight.specialPrice,
      notes: special.sweetHighlight.tastingNotes,
    },
    { type: 'separator', text: '✦' },
    { type: 'perk', text: special.pairPerk },
    { type: 'separator', text: '✦' },
    { type: 'quote', text: `“${special.baristaQuote}”` },
  ];

  return (
    <div className="w-full relative z-20 mb-8 sm:mb-12">
      {/* 1. Subtle Marquee Ribbon Banner */}
      <div className="w-full bg-gradient-to-r from-[#281015] via-[#351016] to-[#240c11] text-[#faf6ee] border-y border-[#c9833a]/30 shadow-[0_4px_20px_-4px_rgba(53,16,22,0.35)] relative overflow-hidden group">
        {/* Subtle Ambient Gold Hairline on top and bottom */}
        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#f4d19b]/40 to-transparent" />
        <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[#c9833a]/30 to-transparent" />

        <div className="max-w-7xl mx-auto flex items-center justify-between">
          {/* Left Fixed Kicker Pill */}
          <div className="shrink-0 flex items-center gap-2 px-3 sm:px-5 py-2.5 bg-[#20080d]/90 border-r border-[#c9833a]/25 z-10 backdrop-blur-md">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#f4d19b] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#c9833a]" />
            </span>
            <div className="flex items-center gap-1.5 font-sans font-bold text-[10px] sm:text-[11px] uppercase tracking-[0.2em] text-[#f4d19b]">
              <Sparkles className="w-3 h-3 text-[#c9833a]" />
              <span className="hidden xs:inline">DAILY SPECIALS</span>
              <span className="xs:hidden">TODAY</span>
            </div>
            <span className="hidden md:inline-block w-1 h-1 rounded-full bg-[#c9833a]/60" />
            <span className="hidden md:inline-block font-serif text-[11px] italic text-[#d8cbb8]">
              {special.dayName}
            </span>
          </div>

          {/* Center Infinite Smooth Marquee Track */}
          <div
            className="flex-1 overflow-hidden whitespace-nowrap py-2 relative flex items-center mask-gradient"
            tabIndex={0}
            aria-label="Daily Specials continuous ticker"
          >
            {/* Inline track 1 & 2 for smooth continuous looping animation */}
            <div className="animate-marquee-continuous gap-6 sm:gap-8 will-change-transform">
              {[0, 1].map((copyIndex) => (
                <div key={copyIndex} className="inline-flex items-center gap-6 sm:gap-8">
                  {/* Coffee Special Item */}
                  <button
                    type="button"
                    onClick={() => setIsExpanded((prev) => !prev)}
                    className="inline-flex items-center gap-2 hover:text-[#f4d19b] transition-colors cursor-pointer text-left"
                  >
                    <span className="w-4 h-4 rounded-full bg-[#c9833a]/25 text-[#f4d19b] flex items-center justify-center shrink-0">
                      <Coffee className="w-2.5 h-2.5" />
                    </span>
                    <span className="font-sans text-[10px] uppercase tracking-wider text-[#d8cbb8]/80 font-medium">
                      Coffee:
                    </span>
                    <span className="font-serif font-bold text-xs sm:text-sm text-[#faf6ee] underline decoration-[#c9833a]/50 underline-offset-2">
                      {special.coffeeHighlight.title}
                    </span>
                    <span className="font-mono text-xs text-[#f4d19b] font-semibold bg-white/10 px-1.5 py-0.2 rounded">
                      {special.coffeeHighlight.specialPrice}
                    </span>
                  </button>

                  <span className="text-[#c9833a]/60 text-xs">✦</span>

                  {/* Sweet Special Item */}
                  <button
                    type="button"
                    onClick={() => setIsExpanded((prev) => !prev)}
                    className="inline-flex items-center gap-2 hover:text-[#f4d19b] transition-colors cursor-pointer text-left"
                  >
                    <span className="w-4 h-4 rounded-full bg-[#c9833a]/25 text-[#f4d19b] flex items-center justify-center shrink-0">
                      <Cookie className="w-2.5 h-2.5" />
                    </span>
                    <span className="font-sans text-[10px] uppercase tracking-wider text-[#d8cbb8]/80 font-medium">
                      Sweet:
                    </span>
                    <span className="font-serif font-bold text-xs sm:text-sm text-[#faf6ee] underline decoration-[#c9833a]/50 underline-offset-2">
                      {special.sweetHighlight.title}
                    </span>
                    <span className="font-mono text-xs text-[#f4d19b] font-semibold bg-white/10 px-1.5 py-0.2 rounded">
                      {special.sweetHighlight.specialPrice}
                    </span>
                  </button>

                  <span className="text-[#c9833a]/60 text-xs">✦</span>

                  {/* Promotion Perk */}
                  <div className="inline-flex items-center gap-1.5 text-xs text-[#f4d19b] font-medium bg-[#c9833a]/15 border border-[#c9833a]/30 px-2 py-0.5 rounded-full">
                    <Flame className="w-3 h-3 text-[#f4d19b]" />
                    <span>{special.pairPerk}</span>
                  </div>

                  <span className="text-[#c9833a]/60 text-xs">✦</span>

                  {/* Tasting Notes */}
                  <span className="font-sans italic text-xs text-[#d8cbb8]/90 max-w-sm truncate hidden sm:inline">
                    {special.coffeeHighlight.tastingNotes}
                  </span>

                  <span className="text-[#c9833a]/60 text-xs">✦</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right Action Button: Toggle Pair Details */}
          <div className="shrink-0 flex items-center gap-1.5 px-3 sm:px-4 py-1.5 bg-[#20080d]/90 border-l border-[#c9833a]/25 z-10 backdrop-blur-md">
            <button
              type="button"
              onClick={() => setIsExpanded((prev) => !prev)}
              className="inline-flex items-center gap-1.5 text-[11px] sm:text-xs font-semibold text-[#f4d19b] hover:text-white px-2.5 py-1 rounded-full bg-white/5 hover:bg-white/15 transition-all cursor-pointer"
              aria-expanded={isExpanded}
              aria-label="Toggle featured daily special pairing details"
            >
              <span>{isExpanded ? 'Hide Details' : 'View Specials'}</span>
              {isExpanded ? (
                <ChevronUp className="w-3 h-3 text-[#c9833a]" />
              ) : (
                <ChevronDown className="w-3 h-3 text-[#c9833a]" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 2. Interactive Expandable Featured Cards Banner */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden bg-[#faf6ef] border-b border-[#ded7c8]"
          >
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
              {/* Header Title & Tagline */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-[#ded7c8]/80">
                <div className="space-y-1">
                  <div className="inline-flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full bg-[#351016] text-[#faf6ee] text-[10px] font-sans font-bold uppercase tracking-wider">
                      {special.dayName} Recommendation
                    </span>
                    <span className="font-serif italic text-sm text-[#c9833a] font-medium">
                      {special.theme}
                    </span>
                  </div>
                  <h3 className="font-serif font-bold text-xl sm:text-2xl text-[#2d1217]">
                    Today's Curated Coffee & Sweet Pairing
                  </h3>
                  <p className="font-sans text-xs sm:text-sm text-[#614f44]">
                    {special.tagline} · {special.baristaQuote}
                  </p>
                </div>

                <div className="shrink-0 flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleAddBoth}
                    className="inline-flex items-center gap-2 bg-gradient-to-r from-[#c9833a] to-[#b7742d] hover:brightness-110 text-[#1b0d09] px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 shadow-sm cursor-pointer active:scale-95"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Order Both Pairing (+2 Stamps)</span>
                  </button>
                </div>
              </div>

              {/* Two Column Grid: Coffee Item & Sweet Item */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                {/* 1. Featured Coffee Card */}
                <div className="relative p-5 rounded-2xl bg-[#351016] text-[#faf6ee] border border-[#c9833a]/40 shadow-sm flex flex-col justify-between overflow-hidden">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-[#c9833a]/10 rounded-full blur-2xl pointer-events-none" />

                  <div className="space-y-3 relative z-10">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-xl bg-[#c9833a]/25 text-[#f4d19b] flex items-center justify-center shrink-0 border border-[#c9833a]/40">
                          <Coffee className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="text-[10px] font-sans font-semibold uppercase tracking-widest text-[#f4d19b]/80 block">
                            Featured Coffee
                          </span>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <h4 className="font-serif font-bold text-lg sm:text-xl text-white">
                              {special.coffeeHighlight.title}
                            </h4>
                            {coffeeProduct?.dietary && (
                              <div className="flex items-center gap-1">
                                {coffeeProduct.dietary.map((tag) => (
                                  <DietaryBadge key={tag} tag={tag} theme="dark" size="xs" />
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      <span className="font-mono text-base font-bold text-[#f4d19b] bg-white/10 px-2.5 py-1 rounded-lg border border-[#c9833a]/30">
                        {special.coffeeHighlight.specialPrice}
                      </span>
                    </div>

                    <p className="font-sans text-xs sm:text-sm text-[#e8dfd1] leading-relaxed">
                      {special.coffeeHighlight.tastingNotes}
                    </p>
                  </div>

                  <div className="pt-4 mt-4 border-t border-white/10 flex items-center justify-between relative z-10">
                    <span className="text-[11px] font-sans text-[#f4d19b]/90 flex items-center gap-1.5">
                      <Sparkles className="w-3 h-3 text-[#c9833a]" />
                      Single-Origin Extraction
                    </span>

                    <button
                      type="button"
                      onClick={(e) =>
                        handleQuickAdd(
                          coffeeProduct,
                          special.coffeeHighlight.title,
                          coffeeProduct ? coffeeProduct.priceNum : 250,
                          'coffee',
                          e,
                        )
                      }
                      className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                        isCoffeeRecentlyAdded
                          ? 'bg-[#2e7d32] text-white'
                          : 'bg-[#faf6ee] text-[#351016] hover:bg-[#c9833a] hover:text-white'
                      }`}
                    >
                      {isCoffeeRecentlyAdded ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>Added</span>
                        </>
                      ) : (
                        <>
                          <Plus className="w-3.5 h-3.5" />
                          <span>Add to Tray</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* 2. Featured Sweet Card */}
                <div className="relative p-5 rounded-2xl bg-[#faf6ef] text-[#2d1217] border border-[#ded7c8] shadow-sm flex flex-col justify-between overflow-hidden">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-[#c9833a]/5 rounded-full blur-2xl pointer-events-none" />

                  <div className="space-y-3 relative z-10">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-xl bg-[#351016]/10 text-[#6b3a1f] flex items-center justify-center shrink-0 border border-[#6b3a1f]/20">
                          <Cookie className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="text-[10px] font-sans font-semibold uppercase tracking-widest text-[#8a7a6f] block">
                            Featured Sweet
                          </span>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <h4 className="font-serif font-bold text-lg sm:text-xl text-[#2d1217]">
                              {special.sweetHighlight.title}
                            </h4>
                            {sweetProduct?.dietary && (
                              <div className="flex items-center gap-1">
                                {sweetProduct.dietary.map((tag) => (
                                  <DietaryBadge key={tag} tag={tag} theme="cream" size="xs" />
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      <span className="font-mono text-base font-bold text-[#6b3a1f] bg-[#eee9de] px-2.5 py-1 rounded-lg border border-[#ded7c8]">
                        {special.sweetHighlight.specialPrice}
                      </span>
                    </div>

                    <p className="font-sans text-xs sm:text-sm text-[#59493f] leading-relaxed">
                      {special.sweetHighlight.tastingNotes}
                    </p>
                  </div>

                  <div className="pt-4 mt-4 border-t border-[#ded7c8] flex items-center justify-between relative z-10">
                    <span className="text-[11px] font-sans text-[#6b3a1f] flex items-center gap-1.5">
                      <Tag className="w-3 h-3 text-[#c9833a]" />
                      Fresh Miliana Patisserie
                    </span>

                    <button
                      type="button"
                      onClick={(e) =>
                        handleQuickAdd(
                          sweetProduct,
                          special.sweetHighlight.title,
                          sweetProduct ? sweetProduct.priceNum : 350,
                          'sweets',
                          e,
                        )
                      }
                      className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                        isSweetRecentlyAdded
                          ? 'bg-[#2e7d32] text-white'
                          : 'bg-[#351016] text-[#faf6ee] hover:bg-[#c9833a] hover:text-white'
                      }`}
                    >
                      {isSweetRecentlyAdded ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>Added</span>
                        </>
                      ) : (
                        <>
                          <Plus className="w-3.5 h-3.5" />
                          <span>Add to Tray</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
