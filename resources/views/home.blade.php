@extends('layouts.master')

@if(session('success'))
  <div id="success-alert" class="alert alert-success position-fixed top-0 end-0 m-4 shadow rounded" style="z-index: 1050;">
    {{ session('success') }}
  </div>
@endif

@section('content')
      <!-- Hero Section -->
    <section id="hero" class="hero section light-background">

      <div class="container">
        <div class="row gy-4 justify-content-center justify-content-lg-between">
          <div class="col-lg-5 order-2 order-lg-1 d-flex flex-column justify-content-center">
            <h1 data-aos="fade-up">Enjoy Your Healthy<br>Delicious Food</h1>
            <p data-aos="fade-up" data-aos-delay="100">BiteBarakah is a Shariah-compliant dessert ordering web app that brings together sweetness and blessings in every bite. From modern pastries to traditional halal treats, users can explore a variety of desserts through a simple, user-friendly platform — all prepared with love and barakah. 🍰🌙✨</p>
            <div class="d-flex" data-aos="fade-up" data-aos-delay="200">
              <a href="https://www.youtube.com/watch?v=Y7f98aduVJ8" class="glightbox btn-watch-video d-flex align-items-center"><i class="bi bi-play-circle"></i><span>Watch Video</span></a>
            </div>
          </div>
          <div class="col-lg-5 order-1 order-lg-2 wow" data-aos="zoom-out">
           <img src="{{ asset('assets/img/wow.png') }}" class="img-fluid" style="max-width: 500px;" alt="Yummy dessert">

          </div>
        </div>
      </div>




    </section><!-- /Hero Section -->

    <!-- About Section -->
    <section id="about" class="about section">

      <!-- Section Title -->
      <div class="container section-title" data-aos="fade-up">
        <h2>About Us<br></h2>
        <p><span>Learn More</span> <span class="description-title">About Us</span></p>
      </div><!-- End Section Title -->

      <div class="container">

        <div class="row gy-4">
          <div class="col-lg-7" data-aos="fade-up" data-aos-delay="100">
            <img src="assets/img/about.jpg" class="img-fluid mb-4" alt="">

          </div>
          <div class="col-lg-5" data-aos="fade-up" data-aos-delay="250">
            <div class="content ps-0 ps-lg-5">
              <p class="fst-italic">
               Welcome to BiteBarakah, where every dessert is sprinkled with love and a touch of barakah! 💕✨

                Founded with the passion to sweeten everyday moments, BiteBarakah brings you a delightful variety of Shariah-compliant desserts—from traditional Malay kuih to modern cute confections and refreshing cold treats. Whether you’re craving a bite of nostalgia or a trendy sweet indulgence, we’ve got something for every dessert lover! 🧁🍮

                💫 Our mission is to create not only delicious but also blessed bites—crafted with care, halal ingredients, and a whole lotta heart. We aim to bring joy to our community, one dessert at a time, while supporting ethical practices and values.

                🫶 So whether you're ordering a treat, browsing our menu, or just craving something sweet—thank you for letting BiteBarakah be a part of your day. We hope you find more than just flavor in our desserts—we hope you find a little barakah, too! 💖

            </p>


              <div class="position-relative mt-4">
                <img src="assets/img/about-2.jpg" class="img-fluid" alt="">
                <a href="https://www.youtube.com/watch?v=Y7f98aduVJ8" class="glightbox pulsating-play-btn"></a>
              </div>
            </div>
          </div>
        </div>

      </div>

    </section><!-- /About Section -->

    <!-- Why Us Section -->
    <section id="why-us" class="why-us section light-background">

      <div class="container">

        <div class="row gy-4">

          <div class="col-lg-4" data-aos="fade-up" data-aos-delay="100">
            <div class="why-box">
              <h3>Why Choose BiteBarakah</h3>
              <p>
                At BiteBarakah, we don’t just serve desserts—we share joy, tradition, and love in every bite. Our treats are handmade with care, crafted to follow Shariah principles, and designed to delight both the heart and the palate. Whether you're craving something classic, cute, or cool, we promise a bite full of barakah! 🍮💕
              </p>
              <div class="text-center">
                <a href="#" class="more-btn"><span>Learn More</span> <i class="bi bi-chevron-right"></i></a>
              </div>
            </div>
          </div><!-- End Why Box -->

          <div class="col-lg-8 d-flex align-items-stretch">
            <div class="row gy-4" data-aos="fade-up" data-aos-delay="200">

              <div class="col-xl-4">
                <div class="icon-box d-flex flex-column justify-content-center align-items-center">
                  <i class="bi bi-clipboard-data"></i>
                  <h4>Shariah-Compliant & Heartfelt</h4>
                  <p>Every dessert is prepared with halal ingredients and love, so you can indulge without worry. We aim to spread sweetness in a way that aligns with Islamic values. ✨🕌</p>
                </div>
              </div><!-- End Icon Box -->

              <div class="col-xl-4" data-aos="fade-up" data-aos-delay="300">
                <div class="icon-box d-flex flex-column justify-content-center align-items-center">
                  <i class="bi bi-gem"></i>
                  <h4>Unique Dessert Variety</h4>
                  <p>From traditional Malay kuih to trendy cold treats and adorable character sweets—BiteBarakah has something for every craving and celebration! 🌈🍨</p>
                </div>
              </div><!-- End Icon Box -->

              <div class="col-xl-4" data-aos="fade-up" data-aos-delay="400">
                <div class="icon-box d-flex flex-column justify-content-center align-items-center">
                  <i class="bi bi-inboxes"></i>
                  <h4>Convenient Ordering & Delivery</h4>
                  <p>Whether it’s for a gift, event, or your own sweet tooth, our web app makes it easy to place orders anytime, anywhere. Fast, easy, and always fresh~ 📦📱</p>
                </div>
              </div><!-- End Icon Box -->

            </div>
          </div>

        </div>

      </div>

    </section><!-- /Why Us Section -->

    <!-- Stats Section -->
    <section id="stats" class="stats section dark-background">

      <img src="assets/img/stats-bg.jpg" alt="" data-aos="fade-in">

      <div class="container position-relative" data-aos="fade-up" data-aos-delay="100">

        <div class="row gy-4">

          <div class="col-lg-3 col-md-6">
            <div class="stats-item text-center w-100 h-100">
              <span data-purecounter-start="0" data-purecounter-end="232" data-purecounter-duration="1" class="purecounter"></span>
              <p>Clients</p>
            </div>
          </div><!-- End Stats Item -->

          <div class="col-lg-3 col-md-6">
            <div class="stats-item text-center w-100 h-100">
              <span data-purecounter-start="0" data-purecounter-end="521" data-purecounter-duration="1" class="purecounter"></span>
              <p>Projects</p>
            </div>
          </div><!-- End Stats Item -->

          <div class="col-lg-3 col-md-6">
            <div class="stats-item text-center w-100 h-100">
              <span data-purecounter-start="0" data-purecounter-end="1453" data-purecounter-duration="1" class="purecounter"></span>
              <p>Hours Of Support</p>
            </div>
          </div><!-- End Stats Item -->

          <div class="col-lg-3 col-md-6">
            <div class="stats-item text-center w-100 h-100">
              <span data-purecounter-start="0" data-purecounter-end="32" data-purecounter-duration="1" class="purecounter"></span>
              <p>Workers</p>
            </div>
          </div><!-- End Stats Item -->

        </div>

      </div>

    </section><!-- /Stats Section -->

    <!-- Menu Section -->
    <!-- 🍰 Desserts Section -->
<section id="desserts" class="menu section">

  <!-- Section Title -->
  <div class="container section-title" data-aos="fade-up">
    <h2>Our Desserts</h2>
    <p><span>Taste the Blessing of</span> <span class="description-title">BiteBarakah</span></p>
  </div><!-- End Section Title -->

  <div class="container">

    <!-- Navigation Tabs -->
    <ul class="nav nav-tabs d-flex justify-content-center" data-aos="fade-up" data-aos-delay="100">
      <li class="nav-item">
        <a class="nav-link active show" data-bs-toggle="tab" data-bs-target="#desserts-malay">
          <h4>🍮 Malay Desserts</h4>
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link" data-bs-toggle="tab" data-bs-target="#desserts-cold">
          <h4>❄️ Cold Desserts</h4>
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link" data-bs-toggle="tab" data-bs-target="#desserts-cute">
          <h4>🍓 Cute Desserts</h4>
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link" data-bs-toggle="tab" data-bs-target="#desserts-others">
          <h4>🍪 Others</h4>
        </a>
      </li>
    </ul>

    <!-- Tabs Content -->
    <div class="tab-content" data-aos="fade-up" data-aos-delay="200">

      <!-- 🍮 Malay Desserts -->
      <div class="tab-pane fade active show" id="desserts-malay">
        <div class="tab-header text-center">
          <p>Desserts</p>
          <h3>Malay Desserts</h3>
        </div>
        <div class="row gy-5">

          <!-- Kuih Item Example -->
          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay1.jpg" class="menu-img img-fluid" alt="">
            <h4>Ondeh-Ondeh</h4>
            <p class="ingredients">Glutinous rice balls with gula melaka & coconut</p>
            <p class="price">RM3.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay2.jpg" class="menu-img img-fluid" alt="">
            <h4>Kuih Lapis</h4>
            <p class="ingredients">Colorful layered steamed cake</p>
            <p class="price">RM2.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay3.jpg" class="menu-img img-fluid" alt="">
            <h4>Seri Muka</h4>
            <p class="ingredients">Colorful layered steamed cake</p>
            <p class="price">RM2.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay4.jpg" class="menu-img img-fluid" alt="">
            <h4>Kuih Ketayap</h4>
            <p class="ingredients">Colorful layered steamed cake</p>
            <p class="price">RM2.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay5.jpg" class="menu-img img-fluid" alt="">
            <h4>Kuih Kaswi</h4>
            <p class="ingredients">Colorful layered steamed cake</p>
            <p class="price">RM2.50</p>
          </div>

         <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/malay6.jpg" class="menu-img img-fluid" alt="">
            <h4>Kuih Cara Manis</h4>
            <p class="ingredients">Colorful layered steamed cake</p>
            <p class="price">RM2.50</p>
          </div>
        </div>
      </div>

      <!-- ❄️ Cold Desserts -->
      <div class="tab-pane fade" id="desserts-cold">
        <div class="tab-header text-center">
          <p>Desserts</p>
          <h3>Cold Desserts</h3>
        </div>
        <div class="row gy-5">

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/chocolate.jpg" class="menu-img img-fluid" alt="">
            <h4>Chocolate Ice Cream</h4>
            <p class="ingredients">Rich cocoa delight, served cold</p>
            <p class="price">RM4.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/jellycups.jpg" class="menu-img img-fluid" alt="">
            <h4>Fruit Jelly Cups</h4>
            <p class="ingredients">Mixed fruit jelly in cute mini cups</p>
            <p class="price">RM3.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/cendol.jpg" class="menu-img img-fluid" alt="">
            <h4>Cendol</h4>
            <p class="ingredients">Mixed fruit jelly in cute mini cups</p>
            <p class="price">RM3.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/sagu.jpg" class="menu-img img-fluid" alt="">
            <h4>Sago Gula Melaka</h4>
            <p class="ingredients">Mixed fruit jelly in cute mini cups</p>
            <p class="price">RM3.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/mango.jpg" class="menu-img img-fluid" alt="">
            <h4>Mango Pudding</h4>
            <p class="ingredients">Mixed fruit jelly in cute mini cups</p>
            <p class="price">RM3.50</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/strawberry.jpg" class="menu-img img-fluid" alt="">
            <h4>Strawberry Ice Blended</h4>
            <p class="ingredients">Mixed fruit jelly in cute mini cups</p>
            <p class="price">RM3.50</p>
          </div>


        </div>
      </div>

      <!-- 🍓 Cute Desserts -->
      <div class="tab-pane fade" id="desserts-cute">
        <div class="tab-header text-center">
          <p>Desserts</p>
          <h3>Cute Desserts</h3>
        </div>
        <div class="row gy-5">

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/dango.jpg" class="menu-img img-fluid" alt="">
            <h4>Hanami Dango</h4>
            <p class="ingredients">Mini frosted cake with kawaii design</p>
            <p class="price">RM15.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/daikufu.jpg" class="menu-img img-fluid" alt="">
            <h4>Ichigo Daifuku</h4>
            <p class="ingredients">Crunchy outside, soft inside – adorable faces!</p>
            <p class="price">RM8.00 (3pcs)</p>
          </div>

           <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/bento.jpg" class="menu-img img-fluid" alt="">
            <h4>Kyaraben</h4>
            <p class="ingredients">Character Bento Desserts</p>
            <p class="price">RM8.00 (3pcs)</p>
          </div>

           <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/unicorn.jpg" class="menu-img img-fluid" alt="">
            <h4>Unicorn Cupcakes</h4>
            <p class="ingredients">Character Bento Desserts</p>
            <p class="price">RM8.00 (3pcs)</p>
          </div>

           <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/tart.jpg" class="menu-img img-fluid" alt="">
            <h4>Berry Tarts</h4>
            <p class="ingredients">Character Bento Desserts</p>
            <p class="price">RM8.00 (3pcs)</p>
          </div>

        </div>
      </div>

      <!-- 🍪 Others -->
      <div class="tab-pane fade" id="desserts-others">
        <div class="tab-header text-center">
          <p>Desserts</p>
          <h3>Others</h3>
        </div>
        <div class="row gy-5">

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/fudgy.jpg" class="menu-img img-fluid" alt="">
            <h4>Fudgy Brownies</h4>
            <p class="ingredients">Thick, rich chocolate brownies</p>
            <p class="price">RM5.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/cookies.jpg" class="menu-img img-fluid" alt="">
            <h4>Bhocolate Bhip Bookies</h4>
            <p class="ingredients">Colorful glaze, fluffy texture</p>
            <p class="price">RM3.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/Banana-Bread.jpg" class="menu-img img-fluid" alt="">
            <h4>Chocolate Banana Bread</h4>
            <p class="ingredients">Colorful glaze, fluffy texture</p>
            <p class="price">RM3.00</p>
          </div>

          <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/pandan.jpg" class="menu-img img-fluid" alt="">
            <h4>Pandan Cupcakes</h4>
            <p class="ingredients">Colorful glaze, fluffy texture</p>
            <p class="price">RM3.00</p>
          </div>

           <div class="col-lg-4 menu-item">
            <img src="assets/img/desserts/Cheesecakes.jpg" class="menu-img img-fluid" alt="">
            <h4>Cheesecakes</h4>
            <p class="ingredients">Colorful glaze, fluffy texture</p>
            <p class="price">RM3.00</p>
          </div>

        </div>
      </div>

    </div>
  </div>
</section>
<!-- /Menu Section -->

    <!-- Testimonials Section -->
    <section id="testimonials" class="testimonials section light-background">

      <!-- Section Title -->
      <div class="container section-title" data-aos="fade-up">
        <h2>TESTIMONIALS</h2>
        <p>What Are They <span class="description-title">Saying About Us</span></p>
      </div><!-- End Section Title -->

      <div class="container" data-aos="fade-up" data-aos-delay="100">

        <div class="swiper init-swiper">
          <script type="application/json" class="swiper-config">
            {
              "loop": true,
              "speed": 600,
              "autoplay": {
                "delay": 5000
              },
              "slidesPerView": "auto",
              "pagination": {
                "el": ".swiper-pagination",
                "type": "bullets",
                "clickable": true
              }
            }
          </script>
          <div class="swiper-wrapper">

            <div class="swiper-slide">
              <div class="testimonial-item">
                <div class="row gy-4 justify-content-center">
                  <div class="col-lg-6">
                    <div class="testimonial-content">
                      <p>
                        <i class="bi bi-quote quote-icon-left"></i>
                        <span>Proin iaculis purus consequat sem cure digni ssim donec porttitora entum suscipit rhoncus. Accusantium quam, ultricies eget id, aliquam eget nibh et. Maecen aliquam, risus at semper.</span>
                        <i class="bi bi-quote quote-icon-right"></i>
                      </p>
                      <h3>Saul Goodman</h3>
                      <h4>Ceo &amp; Founder</h4>
                      <div class="stars">
                        <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i>
                      </div>
                    </div>
                  </div>
                  <div class="col-lg-2 text-center">
                    <img src="assets/img/testimonials/testimonials-1.jpg" class="img-fluid testimonial-img" alt="">
                  </div>
                </div>
              </div>
            </div><!-- End testimonial item -->

            <div class="swiper-slide">
              <div class="testimonial-item">
                <div class="row gy-4 justify-content-center">
                  <div class="col-lg-6">
                    <div class="testimonial-content">
                      <p>
                        <i class="bi bi-quote quote-icon-left"></i>
                        <span>Export tempor illum tamen malis malis eram quae irure esse labore quem cillum quid cillum eram malis quorum velit fore eram velit sunt aliqua noster fugiat irure amet legam anim culpa.</span>
                        <i class="bi bi-quote quote-icon-right"></i>
                      </p>
                      <h3>Sara Wilsson</h3>
                      <h4>Designer</h4>
                      <div class="stars">
                        <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i>
                      </div>
                    </div>
                  </div>
                  <div class="col-lg-2 text-center">
                    <img src="assets/img/testimonials/testimonials-2.jpg" class="img-fluid testimonial-img" alt="">
                  </div>
                </div>
              </div>
            </div><!-- End testimonial item -->

            <div class="swiper-slide">
              <div class="testimonial-item">
                <div class="row gy-4 justify-content-center">
                  <div class="col-lg-6">
                    <div class="testimonial-content">
                      <p>
                        <i class="bi bi-quote quote-icon-left"></i>
                        <span>Enim nisi quem export duis labore cillum quae magna enim sint quorum nulla quem veniam duis minim tempor labore quem eram duis noster aute amet eram fore quis sint minim.</span>
                        <i class="bi bi-quote quote-icon-right"></i>
                      </p>
                      <h3>Jena Karlis</h3>
                      <h4>Store Owner</h4>
                      <div class="stars">
                        <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i>
                      </div>
                    </div>
                  </div>
                  <div class="col-lg-2 text-center">
                    <img src="assets/img/testimonials/testimonials-3.jpg" class="img-fluid testimonial-img" alt="">
                  </div>
                </div>
              </div>
            </div><!-- End testimonial item -->

            <div class="swiper-slide">
              <div class="testimonial-item">
                <div class="row gy-4 justify-content-center">
                  <div class="col-lg-6">
                    <div class="testimonial-content">
                      <p>
                        <i class="bi bi-quote quote-icon-left"></i>
                        <span>Fugiat enim eram quae cillum dolore dolor amet nulla culpa multos export minim fugiat minim velit minim dolor enim duis veniam ipsum anim magna sunt elit fore quem dolore labore illum veniam.</span>
                        <i class="bi bi-quote quote-icon-right"></i>
                      </p>
                      <h3>John Larson</h3>
                      <h4>Entrepreneur</h4>
                      <div class="stars">
                        <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i>
                      </div>
                    </div>
                  </div>
                  <div class="col-lg-2 text-center">
                    <img src="assets/img/testimonials/testimonials-4.jpg" class="img-fluid testimonial-img" alt="">
                  </div>
                </div>
              </div>
            </div><!-- End testimonial item -->

          </div>
          <div class="swiper-pagination"></div>
        </div>

      </div>

    </section><!-- /Testimonials Section -->

    <!-- Events Section -->
    <section id="events" class="events section">

      <div class="container-fluid" data-aos="fade-up" data-aos-delay="100">

        <div class="swiper init-swiper">
          <script type="application/json" class="swiper-config">
            {
              "loop": true,
              "speed": 600,
              "autoplay": {
                "delay": 5000
              },
              "slidesPerView": "auto",
              "pagination": {
                "el": ".swiper-pagination",
                "type": "bullets",
                "clickable": true
              },
              "breakpoints": {
                "320": {
                  "slidesPerView": 1,
                  "spaceBetween": 40
                },
                "1200": {
                  "slidesPerView": 3,
                  "spaceBetween": 1
                }
              }
            }
          </script>
          <div class="swiper-wrapper">

            <div class="swiper-slide event-item d-flex flex-column justify-content-end" style="background-image: url(assets/img/events-1.jpg)">
              <h3>Custom Parties</h3>
              <div class="price align-self-start">$99</div>
              <p class="description">
                Quo corporis voluptas ea ad. Consectetur inventore sapiente ipsum voluptas eos omnis facere. Enim facilis veritatis id est rem repudiandae nulla expedita quas.
              </p>
            </div><!-- End Event item -->

            <div class="swiper-slide event-item d-flex flex-column justify-content-end" style="background-image: url(assets/img/events-2.jpg)">
              <h3>Private Parties</h3>
              <div class="price align-self-start">$289</div>
              <p class="description">
                In delectus sint qui et enim. Et ab repudiandae inventore quaerat doloribus. Facere nemo vero est ut dolores ea assumenda et. Delectus saepe accusamus aspernatur.
              </p>
            </div><!-- End Event item -->

            <div class="swiper-slide event-item d-flex flex-column justify-content-end" style="background-image: url(assets/img/events-3.jpg)">
              <h3>Birthday Parties</h3>
              <div class="price align-self-start">$499</div>
              <p class="description">
                Laborum aperiam atque omnis minus omnis est qui assumenda quos. Quis id sit quibusdam. Esse quisquam ducimus officia ipsum ut quibusdam maxime. Non enim perspiciatis.
              </p>
            </div><!-- End Event item -->

            <div class="swiper-slide event-item d-flex flex-column justify-content-end" style="background-image: url(assets/img/events-4.jpg)">
              <h3>Wedding Parties</h3>
              <div class="price align-self-start">$899</div>
              <p class="description">
                Laborum aperiam atque omnis minus omnis est qui assumenda quos. Quis id sit quibusdam. Esse quisquam ducimus officia ipsum ut quibusdam maxime. Non enim perspiciatis.
              </p>
            </div><!-- End Event item -->

          </div>
          <div class="swiper-pagination"></div>
        </div>

      </div>

    </section><!-- /Events Section -->


    </section><!-- /Gallery Section -->

    <!-- Contact Section -->
    <section id="contact" class="contact section">

      <!-- Section Title -->
      <div class="container section-title" data-aos="fade-up">
        <h2>Contact</h2>
        <p><span>Need Help?</span> <span class="description-title">Contact Us</span></p>
      </div><!-- End Section Title -->

      <div class="container" data-aos="fade-up" data-aos-delay="100">

        <div class="mb-5">
          <iframe style="width: 100%; height: 400px;" src="https://www.google.com/maps/embed?pb=!1m14!1m8!1m3!1d12097.433213460943!2d-74.0062269!3d40.7101282!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x0%3A0xb89d1fe6bc499443!2sDowntown+Conference+Center!5e0!3m2!1smk!2sbg!4v1539943755621" frameborder="0" allowfullscreen=""></iframe>
        </div><!-- End Google Maps -->

        <div class="row gy-4">

          <div class="col-md-6">
            <div class="info-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="200">
              <i class="icon bi bi-geo-alt flex-shrink-0"></i>
              <div>
                <h3>Address</h3>
                <p>A108 Adam Street, New York, NY 535022</p>
              </div>
            </div>
          </div><!-- End Info Item -->

          <div class="col-md-6">
            <div class="info-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="300">
              <i class="icon bi bi-telephone flex-shrink-0"></i>
              <div>
                <h3>Call Us</h3>
                <p>+1 5589 55488 55</p>
              </div>
            </div>
          </div><!-- End Info Item -->

          <div class="col-md-6">
            <div class="info-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="400">
              <i class="icon bi bi-envelope flex-shrink-0"></i>
              <div>
                <h3>Email Us</h3>
                <p>info@example.com</p>
              </div>
            </div>
          </div><!-- End Info Item -->

          <div class="col-md-6">
            <div class="info-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="500">
              <i class="icon bi bi-clock flex-shrink-0"></i>
              <div>
                <h3>Opening Hours<br></h3>
                <p><strong>Mon-Sat:</strong> 11AM - 23PM; <strong>Sunday:</strong> Closed</p>
              </div>
            </div>
          </div><!-- End Info Item -->

        </div>

        <form action="forms/contact.php" method="post" class="php-email-form" data-aos="fade-up" data-aos-delay="600">
          <div class="row gy-4">

            <div class="col-md-6">
              <input type="text" name="name" class="form-control" placeholder="Your Name" required="">
            </div>

            <div class="col-md-6 ">
              <input type="email" class="form-control" name="email" placeholder="Your Email" required="">
            </div>

            <div class="col-md-12">
              <input type="text" class="form-control" name="subject" placeholder="Subject" required="">
            </div>

            <div class="col-md-12">
              <textarea class="form-control" name="message" rows="6" placeholder="Message" required=""></textarea>
            </div>

            <div class="col-md-12 text-center">
              <div class="loading">Loading</div>
              <div class="error-message"></div>
              <div class="sent-message">Your message has been sent. Thank you!</div>

              <button type="submit">Send Message</button>
            </div>

          </div>
        </form><!-- End Contact Form -->

      </div>

    </section><!-- /Contact Section -->
@endsection
