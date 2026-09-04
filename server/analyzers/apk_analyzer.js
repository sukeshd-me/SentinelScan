import fs from 'node:fs';

/**
 * Safe static analyzer for Android Application Packages (APK)
 */
export async function parseAPK(filePathOrBuffer) {
  let text = '';
  if (typeof filePathOrBuffer === 'string') {
    const data = await fs.promises.readFile(filePathOrBuffer);
    text = data.toString('binary');
  } else {
    text = filePathOrBuffer.toString('binary');
  }

  const findings = [];
  const details = {
    isAPK: false,
    hasManifest: false,
    hasDex: false,
    hasCertificates: false,
    permissions: [],
    highRiskPermissions: []
  };

  const hasAndroidManifest = text.includes('AndroidManifest.xml');
  const hasClassesDex = text.includes('classes.dex');

  if (!hasAndroidManifest && !hasClassesDex) {
    return { ...details, error: 'Not a recognizable Android package' };
  }

  details.isAPK = true;
  details.hasManifest = hasAndroidManifest;
  details.hasDex = hasClassesDex;
  details.hasCertificates = text.includes('META-INF/') && (text.includes('.RSA') || text.includes('.DSA') || text.includes('.EC'));

  // High-risk Android permissions to check
  const dangerousPermissions = [
    { perm: 'android.permission.SEND_SMS', desc: 'Allows application to send SMS without user confirmation (toll fraud / C2)' },
    { perm: 'android.permission.READ_SMS', desc: 'Allows application to read incoming SMS messages (2FA interception)' },
    { perm: 'android.permission.RECEIVE_SMS', desc: 'Allows application to intercept incoming SMS messages' },
    { perm: 'android.permission.SYSTEM_ALERT_WINDOW', desc: 'Allows drawing overlays over other apps (overlay phishing attacks)' },
    { perm: 'android.permission.BIND_ACCESSIBILITY_SERVICE', desc: 'Requests accessibility service access (frequently abused for credential harvesting / auto-clicks)' },
    { perm: 'android.permission.RECORD_AUDIO', desc: 'Allows recording microphone audio without explicit UI notification' },
    { perm: 'android.permission.CAMERA', desc: 'Allows capturing camera images/video' },
    { perm: 'android.permission.ACCESS_FINE_LOCATION', desc: 'Accesses high-accuracy GPS geolocation' },
    { perm: 'android.permission.ACCESS_BACKGROUND_LOCATION', desc: 'Tracks device location constantly in the background' },
    { perm: 'android.permission.REQUEST_INSTALL_PACKAGES', desc: 'Allows downloading and installing secondary APK packages' },
    { perm: 'android.permission.READ_CALL_LOG', desc: 'Accesses phone call logs and contact history' }
  ];

  for (const item of dangerousPermissions) {
    // Both full name and shorthand name search
    const shortName = item.perm.split('.').pop();
    if (text.includes(item.perm) || text.includes(shortName)) {
      details.permissions.push(item.perm);
      details.highRiskPermissions.push(item.perm);

      findings.push({
        severity: 'MEDIUM',
        category: 'STATIC_APK',
        title: `High-Risk Android Permission: ${shortName}`,
        description: item.desc,
        evidence: `Identified permission declaration '${item.perm}' in package manifest.`
      });
    }
  }

  if (!details.hasCertificates) {
    findings.push({
      severity: 'HIGH',
      category: 'STATIC_APK',
      title: 'Unsigned or Stripped Android Package',
      description: 'The APK does not contain standard META-INF signature files (*.RSA, *.DSA).',
      evidence: 'Missing META-INF signing certificates.'
    });
  }

  return {
    ...details,
    findings
  };
}
