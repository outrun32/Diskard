import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type Language = "en" | "ru";

const messages = {
  en: {
    runs: "Runs", overview: "Overview", targets: "Targets", reports: "Reports",
    workspace: "Workspace", collapse: "Collapse sidebar", expand: "Expand sidebar",
    newRun: "New run", runAttack: "Run attack", fullAttack: "Full attack",
    attackMethod: "Attack method", target: "Target", chooseTarget: "Choose a target",
    executionMode: "Execution mode", standardAttack: "Standard attack", llmAttack: "Automatic attack with LLM",
    standardAttackHint: "Uses the fixed, reviewable payload for this attack.",
    llmAttackHint: "LLM proposes and adapts payloads within the configured attempt budget.",
    addTarget: "Add target", addTargetUrl: "Add target URL", loadingTargets: "Loading targets…",
    connectFirst: "Connect a target first", launchTitle: "Launch attack",
    launchDescription: "Choose a target and run a full assessment or one attack method.",
    fullAttackHint: "Runs every available attack and produces one combined report.",
    methodHint: "Runs one attack with its own trace and report.", unavailable: "Unavailable for this target",
    checking: "Checking target…", fixTarget: "Edit target configuration",
    checksLoading: "Loading runs…", loadMore: "Load more", noChecks: "No full attacks yet.",
    fullRuns: "Full attacks", individualRuns: "Individual runs", combinedReport: "Combined report",
    stop: "Stop", completed: "completed", profile: "Profile", scenarios: "attacks",
    language: "Language", navigation: "Primary navigation", skip: "Skip to content",
  },
  ru: {
    runs: "Запуски", overview: "Обзор", targets: "Цели", reports: "Отчёты",
    workspace: "Рабочее пространство", collapse: "Свернуть меню", expand: "Развернуть меню",
    newRun: "Новый запуск", runAttack: "Запустить атаку", fullAttack: "Полная атака",
    attackMethod: "Способ атаки", target: "Цель", chooseTarget: "Выберите цель",
    executionMode: "Режим выполнения", standardAttack: "Стандартная атака", llmAttack: "Автоматическая атака с LLM",
    standardAttackHint: "Использует фиксированный проверяемый payload этой атаки.",
    llmAttackHint: "LLM предлагает и адаптирует payload в пределах заданного бюджета попыток.",
    addTarget: "Добавить цель", addTargetUrl: "Добавить URL цели", loadingTargets: "Загружаем цели…",
    connectFirst: "Сначала подключите цель", launchTitle: "Запуск атаки",
    launchDescription: "Выберите цель и запустите полную проверку или один способ атаки.",
    fullAttackHint: "Запускает все доступные атаки и создаёт один общий отчёт.",
    methodHint: "Запускает одну атаку с отдельной трассировкой и отчётом.", unavailable: "Недоступно для этой цели",
    checking: "Проверяем цель…", fixTarget: "Изменить настройки цели",
    checksLoading: "Загружаем запуски…", loadMore: "Загрузить ещё", noChecks: "Полных атак пока нет.",
    fullRuns: "Полные атаки", individualRuns: "Отдельные запуски", combinedReport: "Общий отчёт",
    stop: "Остановить", completed: "завершено", profile: "Профиль", scenarios: "атак",
    language: "Язык", navigation: "Основная навигация", skip: "К содержимому",
  },
} as const;

type Key = keyof typeof messages.en;
type LanguageContextValue = { language: Language; setLanguage: (language: Language) => void; t: (key: Key) => string };
const LanguageContext = createContext<LanguageContextValue | null>(null);

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguage] = useState<Language>(() => localStorage.getItem("diskard-language") === "ru" ? "ru" : "en");
  useEffect(() => { localStorage.setItem("diskard-language", language); document.documentElement.lang = language; }, [language]);
  const value = useMemo(() => ({ language, setLanguage, t: (key: Key) => messages[language][key] }), [language]);
  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) throw new Error("useLanguage must be used inside LanguageProvider");
  return context;
}
