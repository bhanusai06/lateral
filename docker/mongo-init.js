// MongoDB initialization for LateralShield
db = db.getSiblingDB('lateralshield');

// Create collections with validation
db.createCollection('alerts', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['event_id', 'timestamp', 'severity'],
      properties: {
        event_id:  { bsonType: 'string' },
        timestamp: { bsonType: 'date'   },
        severity:  { enum: ['critical', 'high', 'medium', 'low'] },
      }
    }
  }
});

db.createCollection('honeypots');
db.createCollection('ttp_sessions');
db.createCollection('model_metrics');

// Indexes for fast queries
db.alerts.createIndex({ timestamp: -1 });
db.alerts.createIndex({ severity: 1, timestamp: -1 });
db.alerts.createIndex({ event_id: 1 }, { unique: true });
db.honeypots.createIndex({ id: 1 }, { unique: true });

// Seed demo model metrics
db.model_metrics.insertOne({
  recorded_at: new Date(),
  model: 'ensemble_v1',
  precision: 0.942,
  recall:    0.918,
  f1:        0.930,
  auc_roc:   0.967,
  fpr:       0.062,
  training_samples: 50000
});

print('LateralShield database initialized.');
