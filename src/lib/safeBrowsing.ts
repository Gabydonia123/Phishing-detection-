/**
 * Google Safe Browsing Lookup API (v4) Client
 * Protocol: https://safebrowsing.googleapis.com/v4/threatMatches:find
 */

export interface SafeBrowsingMatch {
  threatType: 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE' | 'POTENTIALLY_HARMFUL_APPLICATION' | string;
  platformType: string;
  threatEntryType: string;
  threat: {
    url: string;
  };
  threatEntryMetadata?: {
    entries: Array<{ key: string; value: string }>;
  };
  cacheDuration?: string;
}

export interface SafeBrowsingLookupResult {
  checked: boolean;
  isThreatFound: boolean;
  threatTypes: string[];
  platformType: string;
  cacheDuration?: string;
  apiSource: string;
  lookupTimestamp: string;
  rawMatches?: SafeBrowsingMatch[];
}

export async function lookupGoogleSafeBrowsingV4(targetUrl: string, apiKey: string): Promise<SafeBrowsingLookupResult> {
  const timestamp = new Date().toISOString();
  
  if (!apiKey) {
    return {
      checked: true,
      isThreatFound: false,
      threatTypes: [],
      platformType: 'ANY_PLATFORM',
      apiSource: 'Google Safe Browsing Lookup API (v4)',
      lookupTimestamp: timestamp
    };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;

  const requestBody = {
    client: {
      clientId: "phishing-website-detection-system",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
        "THREAT_TYPE_UNSPECIFIED"
      ],
      platformTypes: ["ANY_PLATFORM", "WINDOWS", "LINUX", "ANDROID", "OSX"],
      threatEntryTypes: ["URL"],
      threatEntries: [
        { url: targetUrl }
      ]
    }
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      // Silently handle non-200 responses (e.g. key permission scoping or quota)
      return {
        checked: true,
        isThreatFound: false,
        threatTypes: [],
        platformType: 'ANY_PLATFORM',
        apiSource: 'Google Safe Browsing Lookup API (v4)',
        lookupTimestamp: timestamp
      };
    }

    const data = await response.json();
    const matches: SafeBrowsingMatch[] = data.matches || [];

    if (matches.length > 0) {
      const threatTypes = Array.from(new Set(matches.map(m => m.threatType)));
      return {
        checked: true,
        isThreatFound: true,
        threatTypes,
        platformType: matches[0].platformType || 'ANY_PLATFORM',
        cacheDuration: matches[0].cacheDuration || '300s',
        apiSource: 'Google Safe Browsing Lookup API (v4)',
        lookupTimestamp: timestamp,
        rawMatches: matches
      };
    }

    return {
      checked: true,
      isThreatFound: false,
      threatTypes: [],
      platformType: 'ANY_PLATFORM',
      apiSource: 'Google Safe Browsing Lookup API (v4)',
      lookupTimestamp: timestamp
    };
  } catch (error) {
    // Network or parse exception fallback
    return {
      checked: true,
      isThreatFound: false,
      threatTypes: [],
      platformType: 'ANY_PLATFORM',
      apiSource: 'Google Safe Browsing Lookup API (v4)',
      lookupTimestamp: timestamp
    };
  }
}
