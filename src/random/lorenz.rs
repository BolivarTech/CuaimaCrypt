//! Lorenz attractor system for chaotic number generation.
//!
//! Implements the Lorenz differential equations using Euler method
//! integration, with 20 predefined attractor configurations determined
//! via Chaoscope 0.3.

use super::mersenne_twister::MersenneTwisterPlus;

/// Trait for chaotic attractor systems.
pub trait Attractor {
    /// Sets the initial point for the attractor trajectory.
    fn set_initial_point(&mut self, x: f64, y: f64, z: f64);

    /// Computes the next point in the attractor trajectory.
    fn next_point(&mut self);

    /// Returns the current X coordinate.
    fn x(&self) -> f64;

    /// Returns the current Y coordinate.
    fn y(&self) -> f64;

    /// Returns the current Z coordinate.
    fn z(&self) -> f64;
}

/// Lorenz attractor implementing Euler method integration.
///
/// Implements divergence protection: if any coordinate exceeds |100|,
/// it is replaced with its reciprocal to prevent numerical overflow.
///
/// The 20 predefined configurations cover a range of chaotic behaviors
/// with different Gamma (sigma), Theta (rho), Beta, and DeltaT parameters.
pub struct LorenzAttractor {
    x: f64,
    y: f64,
    z: f64,
    gamma: f64,
    theta: f64,
    beta: f64,
    delta_t: f64,
}

impl Default for LorenzAttractor {
    /// Creates a new attractor with default parameters (type 1) and origin point.
    ///
    /// The initial point is (0, 0, 0). Use [`set_initial_point`](Self::set_initial_point)
    /// and [`set_attractor_type`](Self::set_attractor_type) to configure.
    fn default() -> Self {
        LorenzAttractor {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            gamma: 6.828,
            theta: 9.165,
            beta: 15.026,
            delta_t: 0.114,
        }
    }
}

impl LorenzAttractor {
    /// Creates a new attractor with random initial point.
    ///
    /// Uses the provided PRNG to generate an initial point that is
    /// verified not to be an equilibrium point of the system.
    ///
    /// # Parameters
    /// - `rng`: Mersenne Twister PRNG for initial point generation.
    pub fn new(rng: &mut MersenneTwisterPlus) -> Self {
        let mut attractor = LorenzAttractor {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            gamma: 6.828,
            theta: 9.165,
            beta: 15.026,
            delta_t: 0.114,
        };

        loop {
            let rx = rng.next_double();
            attractor.x = if rx != 0.0 { 1.0 / rx } else { 0.0 };
            let ry = rng.next_double();
            attractor.y = if ry != 0.0 { 1.0 / ry } else { 0.0 };
            let rz = rng.next_double();
            attractor.z = if rz != 0.0 { 1.0 / rz } else { 0.0 };

            if !attractor.verify_equilibrium_point(attractor.x, attractor.y, attractor.z) {
                break;
            }
        }

        attractor
    }

    /// Returns the number of predefined attractor configurations.
    pub fn num_attractor_types() -> usize {
        20
    }

    /// Sets the attractor parameters to one of 20 predefined configurations.
    ///
    /// If `n` is outside the range [0, 19], canonical Lorenz values are used
    /// (Gamma=10, Theta=28, Beta=2.6667, DeltaT=0.01).
    ///
    /// # Parameters
    /// - `n`: Configuration index (0..=19).
    pub fn set_attractor_type(&mut self, n: usize) {
        match n {
            0 => {
                self.gamma = 6.59;
                self.theta = 11.786;
                self.beta = 18.221;
                self.delta_t = 0.095;
            }
            1 => {
                self.gamma = 6.828;
                self.theta = 9.165;
                self.beta = 15.026;
                self.delta_t = 0.114;
            }
            2 => {
                self.gamma = 0.809;
                self.theta = 18.829;
                self.beta = 8.121;
                self.delta_t = 0.099;
            }
            3 => {
                self.gamma = 8.474;
                self.theta = 10.71;
                self.beta = 18.602;
                self.delta_t = 0.092;
            }
            4 => {
                self.gamma = 7.922;
                self.theta = 5.877;
                self.beta = 3.537;
                self.delta_t = 0.158;
            }
            5 => {
                self.gamma = 3.715;
                self.theta = 10.253;
                self.beta = 15.055;
                self.delta_t = 0.119;
            }
            6 => {
                self.gamma = 6.526;
                self.theta = 4.926;
                self.beta = 14.138;
                self.delta_t = 0.15;
            }
            7 => {
                self.gamma = 0.64;
                self.theta = 10.369;
                self.beta = 7.046;
                self.delta_t = 0.169;
            }
            8 => {
                self.gamma = 0.857;
                self.theta = 7.938;
                self.beta = 5.852;
                self.delta_t = 0.222;
            }
            9 => {
                self.gamma = 16.23;
                self.theta = 10.249;
                self.beta = 6.669;
                self.delta_t = 0.079;
            }
            10 => {
                self.gamma = 9.851;
                self.theta = 6.467;
                self.beta = 14.491;
                self.delta_t = 0.121;
            }
            11 => {
                self.gamma = 4.118;
                self.theta = 13.165;
                self.beta = 16.705;
                self.delta_t = 0.098;
            }
            12 => {
                self.gamma = 7.924;
                self.theta = 7.757;
                self.beta = 13.565;
                self.delta_t = 0.124;
            }
            13 => {
                self.gamma = 8.939;
                self.theta = 5.713;
                self.beta = 2.194;
                self.delta_t = 0.151;
            }
            14 => {
                self.gamma = 12.286;
                self.theta = 14.222;
                self.beta = 4.263;
                self.delta_t = 0.041;
            }
            15 => {
                self.gamma = 8.034;
                self.theta = 6.607;
                self.beta = 3.268;
                self.delta_t = 0.137;
            }
            16 => {
                self.gamma = 11.092;
                self.theta = 5.897;
                self.beta = 2.887;
                self.delta_t = 0.132;
            }
            17 => {
                self.gamma = 2.675;
                self.theta = 5.639;
                self.beta = 1.403;
                self.delta_t = 0.181;
            }
            18 => {
                self.gamma = 4.939;
                self.theta = 4.324;
                self.beta = 1.923;
                self.delta_t = 0.253;
            }
            19 => {
                self.gamma = 9.124;
                self.theta = 8.905;
                self.beta = 17.614;
                self.delta_t = 0.101;
            }
            _ => {
                // Canonical Lorenz values
                self.gamma = 10.0;
                self.theta = 28.0;
                self.beta = 2.6666666667;
                self.delta_t = 0.01;
            }
        }
    }

    /// Verifies whether a point is an equilibrium point of the system.
    ///
    /// Checks against the three equilibrium points:
    /// - (0, 0, 0)
    /// - (sqrt(Beta*(Theta-1)), sqrt(Beta*(Theta-1)), Theta-1)
    /// - (-sqrt(Beta*(Theta-1)), -sqrt(Beta*(Theta-1)), Theta-1)
    fn verify_equilibrium_point(&self, xp: f64, yp: f64, zp: f64) -> bool {
        if xp == 0.0 && yp == 0.0 && zp == 0.0 {
            return true;
        }
        let ze = self.theta - 1.0;
        let xe = (self.beta * ze).sqrt();
        let ye = xe;
        if xp == xe && yp == ye && zp == ze {
            return true;
        }
        let xe_neg = -xe;
        if xp == xe_neg && yp == xe_neg && zp == ze {
            return true;
        }
        false
    }

    /// Returns the Gamma (sigma) parameter.
    pub fn gamma(&self) -> f64 {
        self.gamma
    }

    /// Returns the Theta (rho) parameter.
    pub fn theta(&self) -> f64 {
        self.theta
    }

    /// Returns the Beta parameter.
    pub fn beta(&self) -> f64 {
        self.beta
    }

    /// Returns the DeltaT (time step) parameter.
    pub fn delta_t(&self) -> f64 {
        self.delta_t
    }
}

impl Attractor for LorenzAttractor {
    fn set_initial_point(&mut self, x: f64, y: f64, z: f64) {
        self.x = x;
        self.y = y;
        self.z = z;
    }

    fn next_point(&mut self) {
        let xo = self.x;
        let yo = self.y;
        let zo = self.z;

        self.x = xo + (self.gamma * (yo - xo)) * self.delta_t;
        self.y = yo + (xo * (self.theta - zo) - yo) * self.delta_t;
        self.z = zo + (xo * yo - self.beta * zo) * self.delta_t;

        // Divergence protection: replace with reciprocal if |val| > 100
        if self.x.abs() > 100.0 {
            self.x = 1.0 / self.x;
        }
        if self.y.abs() > 100.0 {
            self.y = 1.0 / self.y;
        }
        if self.z.abs() > 100.0 {
            self.z = 1.0 / self.z;
        }
    }

    fn x(&self) -> f64 {
        self.x
    }

    fn y(&self) -> f64 {
        self.y
    }

    fn z(&self) -> f64 {
        self.z
    }
}

impl Drop for LorenzAttractor {
    /// Securely clears attractor coordinates and parameters on drop.
    fn drop(&mut self) {
        self.x = 0.0;
        self.y = 0.0;
        self.z = 0.0;
        self.gamma = 0.0;
        self.theta = 0.0;
        self.beta = 0.0;
        self.delta_t = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attractor_creation() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let attractor = LorenzAttractor::new(&mut rng);
        // Initial point should not be an equilibrium
        assert!(
            !(attractor.x == 0.0 && attractor.y == 0.0 && attractor.z == 0.0),
            "Initial point should not be origin"
        );
    }

    #[test]
    fn test_num_attractor_types() {
        assert_eq!(LorenzAttractor::num_attractor_types(), 20);
    }

    #[test]
    fn test_set_attractor_type_valid() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let mut attractor = LorenzAttractor::new(&mut rng);
        attractor.set_attractor_type(0);
        assert_eq!(attractor.gamma, 6.59);
        assert_eq!(attractor.theta, 11.786);
        assert_eq!(attractor.beta, 18.221);
        assert_eq!(attractor.delta_t, 0.095);
    }

    #[test]
    fn test_set_attractor_type_default() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let mut attractor = LorenzAttractor::new(&mut rng);
        attractor.set_attractor_type(99); // out of range
        assert_eq!(attractor.gamma, 10.0);
        assert_eq!(attractor.theta, 28.0);
    }

    #[test]
    fn test_next_point_deterministic() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let mut a1 = LorenzAttractor::new(&mut rng);
        let mut rng2 = MersenneTwisterPlus::with_seed(42);
        let mut a2 = LorenzAttractor::new(&mut rng2);

        for _ in 0..100 {
            a1.next_point();
            a2.next_point();
            assert_eq!(a1.x(), a2.x());
            assert_eq!(a1.y(), a2.y());
            assert_eq!(a1.z(), a2.z());
        }
    }

    #[test]
    fn test_divergence_protection() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let mut attractor = LorenzAttractor::new(&mut rng);
        attractor.set_initial_point(200.0, 200.0, 200.0);
        attractor.next_point();
        // After divergence protection, values should be < 100
        assert!(attractor.x().abs() <= 100.0);
        assert!(attractor.y().abs() <= 100.0);
        assert!(attractor.z().abs() <= 100.0);
    }

    #[test]
    fn test_set_initial_point() {
        let mut rng = MersenneTwisterPlus::with_seed(42);
        let mut attractor = LorenzAttractor::new(&mut rng);
        attractor.set_initial_point(1.0, 2.0, 3.0);
        assert_eq!(attractor.x(), 1.0);
        assert_eq!(attractor.y(), 2.0);
        assert_eq!(attractor.z(), 3.0);
    }
}
