fn main() {
  let info = clops_core::accel::detect();
  println!("{}", serde_json::to_string_pretty(&info).unwrap());
}
