// Static reference data taken from https://api.ilogistic.eu/documentation (api-statuses + OpenAPI specs).

export const ORDER_STATES = [
  "Hiányos fizetési adatok",
  "Hibás",
  "Jóváhagyásra vár",
  "Jóváhagyva",
  "Összekészítés alatt",
  "Csomagolva",
  "Futárnak átadva",
  "Csomagponton várakozik",
  "Szállítás közben megsérült",
  "Hiányos kiszedés",
  "Kiszállítva",
  "Raktárba visszaérkezett",
  "Visszáru",
] as const;

export const INWARD_STATES = ["Várható", "Folyamatban", "Részben átvett", "Átvett", "Beszerzési ár pótlásra vár"] as const;

export const DELIVERY_COMPANIES = [
  "GLS",
  "Foxpost",
  "Személyes átvétel",
  "MPL",
  "DHL",
  "Raklapos szállítás",
  "Pactic Elsődleges",
  "Pactic Másodlagos",
  "Express One",
  "Express One raklapos",
] as const;

export const PAYMENT_TYPES = ["Utánvétes fizetés", "Bankkártyás fizetés", "Átutalásos fizetés"] as const;

export const PRODUCT_CATEGORIES = ["termek", "virtual", "csomag"] as const;

export const REFERENCE = {
  orderStates: {
    values: ORDER_STATES,
    notes: [
      "Orders can no longer be modified or deleted once they reach 'Összekészítés alatt' (being picked).",
      "Final states: 'Hiányos kiszedés', 'Kiszállítva', 'Visszáru'.",
      "'Hiányos kiszedés': an item was out of stock; a copy of the order is created keeping the original foreignId.",
      "'Visszáru': the customer has 6 days to choose reshipment or restocking, otherwise the system restocks automatically.",
    ],
  },
  inwardHandlingStates: {
    values: INWARD_STATES,
    notes: ["Inward handlings can only be edited or deleted while in 'Várható' (expected)."],
  },
  deliveryCompanies: DELIVERY_COMPANIES,
  paymentTypes: PAYMENT_TYPES,
  productCategories: {
    values: PRODUCT_CATEGORIES,
    notes: ["termek = physical product, virtual = virtual product, csomag = bundle/package product"],
  },
  conventions: [
    "Order amounts are assumed to be in the country's official currency; no conversion is done. COD amounts are passed to couriers unchanged.",
    "delivery.phoneNumber / billing.phoneNumber must start with +36 per the API docs.",
    "delivery.country accepts the Hungarian name, ISO 3166 alpha-2 or alpha-3.",
    "Product weight is in grams, width/depth/height in centimetres, price is net HUF.",
    "itemNumber cannot be changed after product creation; barcodes can only be added (max 4).",
  ],
} as const;
