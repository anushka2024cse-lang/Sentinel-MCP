// Client-safe heuristic prompt injection detector (zero Node.js dependencies)
export const INJECTION_PATTERNS = [
  /system\s+override/i,
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|constraints|prompts)/i,
  /reveal\s+(the\s+)?(secret|master|api|system)\s+(key|token|prompt)/i,
  /you\s+are\s+now\s+in\s+unrestricted\s+mode/i,
  /bypass\s+security\s+filter/i,
  /purge\s+database/i
];

export function detectPromptInjection(args: Record<string, unknown> | string): { detected: boolean; matchedSnippet?: string } {
  const text = typeof args === 'string' ? args : JSON.stringify(args);
  for (const pattern of INJECTION_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      return { detected: true, matchedSnippet: match[0] };
    }
  }
  return { detected: false };
}
