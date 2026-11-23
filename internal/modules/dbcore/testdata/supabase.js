import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://abcdefghijklmnopqrst.supabase.co'
const supabaseKey = 'sb_publishable_AbCdEf0123456789xyz_KQ'

export const supabase = createClient(supabaseUrl, supabaseKey)
