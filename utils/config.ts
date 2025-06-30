import type { 
  TernSecureAdminConfig, 
  AdminConfigValidationResult 
} from '../types'

/**
 * Loads Firebase configuration from environment variables
 * @returns {TernSecureConfig} Firebase configuration object
 */
/**
 * Loads Firebase Admin configuration from environment variables
 * @returns {AdminConfig} Firebase Admin configuration object
 */
export const loadAdminConfig = (): TernSecureAdminConfig => ({
  projectId: process.env.FIREBASE_PROJECT_ID || '',
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
  privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
})

/**
 * Validates Firebase Admin configuration
 * @param {AdminConfig} config - Firebase Admin configuration object
 * @returns {ConfigValidationResult} Validation result
 */
export const validateAdminConfig = (config: TernSecureAdminConfig): AdminConfigValidationResult => {
  const requiredFields: (keyof TernSecureAdminConfig)[] = [
    'projectId',
    'clientEmail',
    'privateKey'
  ]

  const errors: string[] = []
  
  requiredFields.forEach(field => {
    if (!config[field]) {
      errors.push(`Missing required field: FIREBASE_${String(field).toUpperCase()}`)
    }
  })

  return {
    isValid: errors.length === 0,
    errors,
    config
  }
}

/**
 * Initializes admin configuration with validation
 * @throws {Error} If configuration is invalid
 */
export const initializeAdminConfig = (): TernSecureAdminConfig => {
  const config = loadAdminConfig()
  const validationResult = validateAdminConfig(config)

  if (!validationResult.isValid) {
    throw new Error(
      `Firebase Admin configuration validation failed:\n${validationResult.errors.join('\n')}`
    )
  }

  return config
}