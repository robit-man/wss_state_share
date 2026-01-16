# server.js Analysis

## Overview
This Node.js application serves as a dual HTTP server and WebSocket hub that drives real-time sensor data flow for mobile "phone twins" visualization. The server processes and broadcasts motion data while serving static assets. TLS termination is explicitly handled by `server.py`, enabling HTTPS access without direct TLS configuration in the Node.js layer.

## Architecture

### HTTP Server
- **Port Configuration**: Uses `PORT` environment variable with fallback to 8080
- **Static Assets**: Serves client-side files (HTML/JS/CSS) from root directory
- **CSP-Safe HTML**: Generates Content Security Policy-compliant HTML responses without unsafe inline scripts

### WebSocket Hub
- **Connection Lifecycle**: 
  - `join` event: Assigns unique client ID and initial state
  - `leave` event: Cleans up peer tracking data
- **Peer Tracking**: Maintains active clients in a Map structure keyed by connection ID
- **Broadcast Logic**: Propagates validated data to all connected peers while bypassing the source client
- **Buffering Safeguards**: Monitors WebSocket `bufferedAmount` to prevent client overflow

### Peer Management
- **ID Generation**: Creates unique client identifiers using crypto randomness
- **State Snapshots**: Maintains current sensor data for each peer
- **Cleanup Protocol**: Removes peer data on disconnect and broadcasts state updates

## Data Flow

1. **Client Submission**: Browser sends sensor data via WebSocket
2. **Server Validation**:
   - GPS: `lat`/`lng` clamped to ±90°/±180°
   - Acceleration: Vectors normalized to 3D space
   - Heading: Validated as 0-360° values
3. **Transformation Pipeline**:
   ```js
   // Quaternion handling
   const qRaw = deviceEulerToQuaternion(alpha, beta, gamma);
   const qOffset = quaternionFromEuler(0, yawCalibration, 0);
   ```
4. **JSON Payload**: Sanitized data formatted as:
   ```json
   {
     "id": "client-123",
     "type": "motion",
     "data": {
       "acc": [0.2, -0.1, 9.8],
       "quat": [0.707, 0, 0.707, 0],
       "gps": {"lat": 37.7749, "lng": -122.4194}
     }
   }
   ```
5. **Broadcast**: Delivers transformed data to all peers

## Sensor Handling

### API Integration
| Sensor Type | Primary API | Fallback |
|-------------|-------------|----------|
| Orientation | AbsoluteOrientationSensor | DeviceOrientationEvent |
| Acceleration | LinearAccelerationSensor | DeviceMotionEvent |
| Gravitational Vector | Accelerometer | DeviceMotionEvent |

### Quaternion Pipeline
1. Converts device Euler angles to raw quaternion
2. Applies yaw calibration via quaternion multiplication
3. Normalizes final quaternion to unit length
4. Clamps to valid mathematical range

### Linear Acceleration Fallback
- When gravity data is unavailable:
  ```js
  if (!hasGravity) {
    acceleration = [
      rawAccel[0] - gravity[0],
      rawAccel[1] - gravity[1],
      rawAccel[2] - gravity[2]
    ];
  }
  ```

## Visualization

### Plane Mode
- **Anchor Frame**: World coordinate system
- **Object Scaling**: Fixed scale for all devices
- **Rotation**: Direct quaternion application

### Sphere Mode
- **Anchor Frame**: Computed via `computeTangentFrameFromUp(upVector)`
- **Positioning**: Uses tangent space projection
- **Label Rendering**: 
  - Dynamic text sizing based on distance
  - World-space billboard orientation

### UI Controls
- Mode switching via radio buttons
- Sphere anchor selection with click interactions
- GPS fallback toggle for positioning

## Key Features

- Real-time performance with 80ms UI throttling
- Battery-friendly sensor polling defaults (100ms intervals)
- Cross-browser compatibility:
  - Safari iOS: Uses webkit-prefixed motion APIs
  - Chrome Android: Leverages standardized sensor APIs
  - Fallback handling for missing absolute orientation
- Input sanitization via regex escaping for HTML labels
- Strict JSON parsing with per-message size limits
- `requestAnimationFrame`-driven rendering loops

## Technical Implementation

### Security Measures
- No template literals for HTML generation
- Strict JSON parsing with error handling
- Per-message size validation (1KB max)
- CSP-compatible asset loading

### Performance Optimizations
- Buffer monitoring for WebSocket flow control
- Object pooling for Three.js vectors
- Throttled UI updates with timestamp checks
- Early validation of sensor data

## Potential Improvements

### Protocol Enhancements
- Binary payloads using Protocol Buffers
- Adaptive frame rate limiting based on network conditions
- Client-side UI debounce to reduce render calls

### Architecture
- Modular separation:
  - `routes.js`: HTTP endpoints
  - `ws-handlers.js`: Connection logic
  - `sensor-bridge.js`: Data pipeline
- Server-side static asset caching
- Structured error logging with reconnection states

## Usage & Deployment

### Setup
```bash
npm install ws three
```

### Execution
1. Start TLS proxy: `python server.py` (handles certificate termination)
2. Launch server: `node server.js`
3. Access via: `https://localhost:8443?ws=wss://localhost:8443/ws`

### Configuration
- Browser URL parameters:
  - `ws`: WebSocket endpoint override
  - `mode`: Default visualization mode (`plane`/`sphere`)
  - `gpsFallback`: Enable GPS-based positioning (`true`/`false`)

## Documentation Conventions

- Headings use `#` with consistent depth
- Sequential processes described with ordered lists
- Code snippets maintained with exact line breaks using `\n`
- Key data structures shown in tabular format
