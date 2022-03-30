use benchmark_simple::*;
use jwt_simple::prelude::*;

fn main() {
    let bench = Bench::new();

    let options = &Options {
        iterations: 1000,
        warmup_iterations: 100,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let kp = RS256KeyPair::generate(2048).unwrap();
    let pk = kp.public_key();

    let claims = Claims::create(Duration::from_hours(2));

    let token = kp.sign(claims.clone()).unwrap();
    let res = bench.run(options, move || kp.sign(claims.clone()).unwrap());
    println!("rsa-2048 - sign: {}", res.throughput(1));

    let res = bench.run(options, move || {
        pk.verify_token::<NoCustomClaims>(&token, Default::default())
    });
    println!("rsa-2048 - verify: {}", res.throughput(1));
}
