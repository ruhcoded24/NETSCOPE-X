import { GoogleGenAI, ThinkingLevel } from '@google/genai';
import { buildRuleBasedInvestigation } from '../core/detectionEngine.ts';
import type { SecurityAlert } from '../core/types.ts';

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

export type SupportedTextModel =
  | 'gemini-4-hydrogen'
  | 'gemini-4-neon'
  | 'gemini-4-carbon'
  | 'gemini-3.1-flash-lite';

export async function investigateAlertWithGemini(
  alert: SecurityAlert,
  requestedModel: SupportedTextModel = 'gemini-4-hydrogen',
  useHighThinking = false,
): Promise<{
  source: 'gemini' | 'rule-based-fallback';
  modelUsed: string;
  analysis: string;
  warning?: string;
}> {
  const ai = getGeminiClient();
  if (!ai) {
    return {
      source: 'rule-based-fallback',
      modelUsed: 'deterministic-rule-engine',
      analysis: buildRuleBasedInvestigation(alert),
      warning: 'GEMINI_API_KEY is not configured; displaying deterministic rule-based investigation.',
    };
  }

  const structuredEvidence = {
    alertId: alert.id,
    timestamp: alert.timestamp,
    sourceIp: alert.sourceIp,
    destinationIp: alert.destinationIp,
    category: alert.category,
    severity: alert.severity,
    riskScore: alert.riskScore,
    riskBreakdown: alert.riskBreakdown,
    classification: alert.classification,
    ruleName: alert.ruleName,
    summary: alert.summary,
    evidence: alert.evidence,
    recommendedSteps: alert.recommendedSteps,
    isSimulated: alert.isSimulated,
  };

  const prompt = [
    'Analyze the following structured cybersecurity detection evidence from NETSCOPE X.',
    'STRICT GROUNDING RULE: Rely ONLY on the JSON evidence provided below. Never invent packet fields, IP reputation, threat actor attribution, or external facts not present in the evidence.',
    'Provide a structured SOC investigation covering:',
    '1. What was observed',
    '2. Why the detection engine flagged it (including the documented risk score formula)',
    '3. Supporting evidence summary',
    '4. Involved endpoints/IPs',
    '5. Technical explanation AND a short beginner-friendly plain-English explanation',
    '6. Possible false-positive explanations',
    '7. Read-only verification & investigation commands (never destructive or offensive commands)',
    '',
    'EVIDENCE JSON:',
    JSON.stringify(structuredEvidence, null, 2),
  ].join('\n');

  const tryModels: SupportedTextModel[] = [requestedModel];
  if (requestedModel !== 'gemini-4-hydrogen') {
    tryModels.push('gemini-4-hydrogen');
  }

  let lastErrorMsg = '';
  for (const model of tryModels) {
    try {
      const config: {
        systemInstruction: string;
        thinkingConfig?: { thinkingLevel: ThinkingLevel };
      } = {
        systemInstruction:
          'You are a senior SOC analyst assistant inside NETSCOPE X. Be concise, accurate, defensive-only, and strictly grounded in the provided structured JSON evidence. Target ~350-550 words.',
      };

      // Use ThinkingLevel.HIGH for gemini-4-carbon or when high thinking is explicitly enabled on Gemini 4 models
      if (
        (model === 'gemini-4-carbon' || useHighThinking) &&
        model !== 'gemini-3.1-flash-lite'
      ) {
        config.thinkingConfig = { thinkingLevel: ThinkingLevel.HIGH };
      }

      const response = await ai.models.generateContent({
        model,
        contents: prompt,
        config,
      });

      const text = response.text?.trim();
      if (!text) {
        throw new Error('Empty response text from Gemini API.');
      }

      return {
        source: 'gemini',
        modelUsed: model,
        analysis: text,
        warning:
          model !== requestedModel
            ? `Model ${requestedModel} was unavailable on the active key; fell back to ${model}.`
            : undefined,
      };
    } catch (err) {
      lastErrorMsg = err instanceof Error ? err.message : String(err);
    }
  }

  return {
    source: 'rule-based-fallback',
    modelUsed: 'deterministic-rule-engine',
    analysis: buildRuleBasedInvestigation(alert),
    warning: `Gemini API unavailable (${lastErrorMsg}). Showing rule-based forensic investigation.`,
  };
}

export async function generateThreatVisualBrief(
  alert: SecurityAlert,
  imageSize: '1K' | '2K' | '4K' = '1K',
): Promise<{
  imageDataUrl?: string;
  modelUsed: string;
  error?: string;
}> {
  const ai = getGeminiClient();
  if (!ai) {
    return {
      modelUsed: 'gemini-3-pro-image-preview',
      error: 'GEMINI_API_KEY is not configured in environment secrets.',
    };
  }

  const prompt = `Clean technical cybersecurity incident diagram illustrating ${alert.category.replace('_', ' ')} network anomaly from ${alert.sourceIp}${alert.destinationIp ? ` toward ${alert.destinationIp}` : ''}, severity ${alert.severity}, dark obsidian #070910 background, crisp cyan #00E5FF and alert red #FF3B5C schematic vector lines, isometric network topology schematic, zero random text, studio technical precision.`;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-pro-image-preview',
      contents: {
        parts: [{ text: prompt }],
      },
      config: {
        imageConfig: {
          aspectRatio: '16:9',
          imageSize,
        },
      },
    });

    for (const part of response.candidates?.[0]?.content?.parts ?? []) {
      if (part.inlineData?.data) {
        const mime = part.inlineData.mimeType ?? 'image/png';
        return {
          imageDataUrl: `data:${mime};base64,${part.inlineData.data}`,
          modelUsed: 'gemini-3-pro-image-preview',
        };
      }
    }

    return {
      modelUsed: 'gemini-3-pro-image-preview',
      error: 'No image data returned by gemini-3-pro-image-preview.',
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      modelUsed: 'gemini-3-pro-image-preview',
      error: `Image generation with gemini-3-pro-image-preview (${imageSize}) requires a billing-enabled API key in Settings > Secrets. (${msg})`,
    };
  }
}
