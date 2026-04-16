-- Migration: 0003_seed_servers.sql
-- Seed VPN servers - UPDATE endpoint IPs AFTER DEPLOYMENT

INSERT INTO servers (id, name, country_code, city, endpoint, public_key, load_percent, features, online)
VALUES 
(
    'a1111111-1111-4111-8111-111111111111',
    'US-East-01',
    'US',
    'New York',
    'YOUR_IP:51820',
    'yrIkET0bnAmEqNjcRp0JuDpMvth6dJ29AF1r9WFC7H8=',
    15,
    ARRAY['wireguard', 'multi-hop'],
    TRUE
),
(
    'b2222222-2222-4222-8222-222222222222',
    'UK-London-01',
    'UK',
    'London',
    'YOUR_IP:51820',
    'yrIkET0bnAmEqNjcRp0JuDpMvth6dJ29AF1r9WFC7H8=',
    25,
    ARRAY['wireguard'],
    TRUE
),
(
    'c3333333-3333-4333-8333-333333333333',
    'DE-Frankfurt-01',
    'DE',
    'Frankfurt',
    'YOUR_IP:51820',
    'yrIkET0bnAmEqNjcRp0JuDpMvth6dJ29AF1r9WFC7H8=',
    10,
    ARRAY['wireguard'],
    TRUE
),
(
    'd4444444-4444-4444-8444-444444444444',
    'SG-Singapore-01',
    'SG',
    'Singapore',
    'YOUR_IP:51820',
    'yrIkET0bnAmEqNjcRp0JuDpMvth6dJ29AF1r9WFC7H8=',
    5,
    ARRAY['wireguard', 'gaming-opt'],
    TRUE
) ON CONFLICT DO NOTHING;