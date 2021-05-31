#ifndef SM3_COMPONENTS_TCC_
#define SM3_COMPONENTS_TCC_

namespace libsnark
{
    const unsigned long sm3_T[64] = {
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
        0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
        0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
        0x879d8a7a, 0xf3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5};

    const unsigned long sm3_H[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

    template <typename FieldT>
    pb_linear_combination_array<FieldT> sm3_default_IV(protoboard<FieldT> &pb)
    {
        pb_linear_combination_array<FieldT> result;
        result.reserve(sm3_digest_size);

        for (size_t i = 0; i < sm3_digest_size; ++i)
        {
            int iv_val = (sm3_H[i / 32] >> (31 - (i % 32))) & 1;

            pb_linear_combination<FieldT> iv_element;
            iv_element.assign(pb, iv_val * ONE);
            iv_element.evaluate(pb);

            result.emplace_back(iv_element);
        }

        return result;
    }

    template <typename FieldT>
    sm3_message_schedule_gadget<FieldT>::sm3_message_schedule_gadget(protoboard<FieldT> &pb,
                                                                     const pb_variable_array<FieldT> &M,
                                                                     const pb_variable_array<FieldT> &packed_W,
                                                                     const pb_variable_array<FieldT> &packed_W_extended,
                                                                     const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                             M(M),
                                                                                                             packed_W(packed_W),
                                                                                                             packed_W_extended(packed_W_extended)
    {
        W_bits.resize(68);
        W_extended_bits.resize(64);

        pack_W.resize(68);
        for (size_t i = 0; i < 16; ++i)
        {
            W_bits[i] = pb_variable_array<FieldT>(M.rbegin() + (15 - i) * 32, M.rbegin() + (16 - i) * 32);
            pack_W[i].reset(new packing_gadget<FieldT>(pb, W_bits[i], packed_W[i], FMT(this->annotation_prefix, " pack_W_%zu", i)));
        }

        /* NB: some of those will be un-allocated */
        p1_input.resize(68);
        p1.resize(68);
        compute_p1_input(68);
        compute_p1.resize(68);
        compute_W.resize(68);
        compute_W_extended.resize(64);

        for (size_t i = 16; i < 68; ++i)
        {
            /* allocate the bit representation of intermediate variables */
            p1_input[i].allocate(pb, 32, FMT(this->annotation_prefix, " p1_input_%zu", i));
            p1[i].allocate(pb, 32, FMT(this->annotation_prefix, " p1_%zu", i));

            /* compute intermediate variables */
            compute_p1_input[i].reset(new parity_gadget<FieldT>(pb, W_bits[i - 16], W_bits[i - 9], W_bits[i - 3], false, 0, 0, 15, p1_input[i], FMT(this->annotation_prefix, " compute_p1_input_%zu", i)));
            compute_p1[i].reset(new permutation_gadget<FieldT>(pb, p1_input[i], p1[i], 0, 15, 23, FMT(this->annotation_prefix, " compute_p1_%zu", i)));

            /* allocate the bit representation of packed_W[i] */
            W_bits[i].allocate(pb, 32, FMT(this->annotation_prefix, " W_bits_%zu", i));

            /* and finally pack bit representations */
            compute_W[i].reset(new parity_gadget<FieldT>(pb, p1[i], W_bits[i - 13], W_bits[i - 6], false, 0, 7, 0, W_bits[i], FMT(this->annotation_prefix, " compute_W_bits_%zu", i)));
            pack_W[i].reset(new packing_gadget<FieldT>(pb, W_bits[i], packed_W[i], FMT(this->annotation_prefix, " pack_W_%zu", i)));
        }

        for (size_t i = 0; i < 64; ++i)
        {
            /* allocate the bit representation of packed_W_extended[i] */
            W_extended_bits[i].allocate(pb, 32, FMT(this->annotation_prefix, " W_extended_bits_%zu", i));

            /* compute W_extended_bits and pack */
            compute_W_extended[i].reset(new parity_gadget<FieldT>(pb, W_bits[i], W_bits[i + 4], ONE, true, 0, 0, 0, W_extended_bits[i], FMT(this->annotation_prefix, " compute_W_entended_bits_%zu", i)));
            packed_W_extended[i].reset(new packing_gadget<FieldT>(pb, W_extended_bits[i], packed_W_extended[i], FMT(this->annotation_prefix, " pack_W_extended_%zu", i)));
        }
    }

    template <typename FieldT>
    void sm3_message_schedule_gadget<FieldT>::generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 16; ++i)
        {
            pack_W[i]->generate_r1cs_constraints(false); // do not enforce bitness here; caller be aware.
        }

        for (size_t i = 16; i < 68; ++i)
        {
            compute_p1_input[i]->generate_r1cs_constraints();
            compute_p1[i]->generate_r1cs_constraints();
            compute_W[i]->generate_r1cs_comstraints();
            pack_W[i]->generate_r1cs_constraints(false);
        }

        for (size_t i = 0; i < 64; i++)
        {
            compute_W_extended[i]->generate_r1cs_constraints();
            pack_W_extended[i]->generate_r1cs_constraints(false);
        }
    }

    template <typename FieldT>
    void sm3_message_schedule_gadget<FieldT>::generate_r1cs_witness()
    {
        for (size_t i = 0; i < 16; ++i)
        {
            pack_W[i]->generate_r1cs_witness_from_bits();
        }

        for (size_t i = 16; i < 68; ++i)
        {
            compute_p1_input[i]->generate_r1cs_witness();
            compute_p1[i]->generate_r1cs_witness();
            compute_W[i]->generate_r1cs_witness();
            pack_W[i]->generate_r1cs_witness_from_bits();
        }

        for (size_t i = 0; i < 64; i++)
        {
            compute_W_extended[i]->generate_r1cs_witness();
            pack_W_extended[i]->generate_r1cs_witness_from_bits();
        }
    }

    template <typename FieldT>
    sm3_round_function_gadget<FieldT>::sm3_round_function_gadget(protoboard<FieldT> &pb,
                                                                 const pb_linear_combination_array<FieldT> &a,
                                                                 const pb_linear_combination_array<FieldT> &b,
                                                                 const pb_linear_combination_array<FieldT> &c,
                                                                 const pb_linear_combination_array<FieldT> &d,
                                                                 const pb_linear_combination_array<FieldT> &e,
                                                                 const pb_linear_combination_array<FieldT> &f,
                                                                 const pb_linear_combination_array<FieldT> &g,
                                                                 const pb_linear_combination_array<FieldT> &h,
                                                                 const pb_variable<FieldT> &W,
                                                                 const pb_variable<FieldT> &W_extended,
                                                                 const unsigned long T,
                                                                 const pb_linear_combination_array<FieldT> &new_a,
                                                                 const pb_linear_combination_array<FieldT> &new_e,
                                                                 const size_t i,
                                                                 const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                         a(a),
                                                                                                         b(b),
                                                                                                         c(c),
                                                                                                         d(d),
                                                                                                         e(e),
                                                                                                         f(f),
                                                                                                         g(g),
                                                                                                         h(h),
                                                                                                         W(W),
                                                                                                         W_extended(W_extended),
                                                                                                         new_a(new_a),
                                                                                                         new_e(new_e),
                                                                                                         i(i),
                                                                                                         T(T)
    {
        // pack E, D, H
        e_packed.allocate(pb, FMT(this->annotation_prefix, " e_packed"));
        d_packed.allocate(pb, FMT(this->annotation_prefix, " d_packed"));
        h_packed.allocate(pb, FMT(this->annotation_prefix, " h_packed"));
        pack_e.reset(new packing_gadget<FieldT>(pb, e, e_packed, FMT(this->annotation_prefix, " pack_e")));
        pack_d.reset(new packing_gadget<FieldT>(pb, d, d_packed, FMT(this->annotation_prefix, " pack_d")));
        pack_h.reset(new packing_gadget<FieldT>(pb, h, h_packed, FMT(this->annotation_prefix, " pack_h")));

        // A<<<12
        a_rotl_bits = rotate_left(a, 12);
        a_rotl_packed.allocate(pb, FMT(this->annotation_prefix, " a_rotl_packed"));
        pack_a_rotl.reset(new packing_gadget<FieldT>(pb, a_rotl_bits, a_rotl_packed, FMT(this->annotation_prefix, " pack_a_rotl")));

        // compute ss1
        ss1_unreduced.allocate(pb, FMT(this->annotation_prefix, " ss1_unreduced"));
        ss1_packed.allocate(pb, FMT(this->annotation_prefix, " ss1_packed"));
        ss1_bits.allocate(pb, 32, FMT(this->annotation_prefix, " ss1_bits"));
        mod_reduce_ss1.reset(new lastbits_gadget<FieldT>(pb, ss1_unreduced, 32 + 1, ss1_packed, ss1_bits, FMT(this->annotation_prefix, " mod_reduce_new_a")));
        ss1_rotl_bits = rotate_left(ss1_bits, 7);
        ss1_rotl_packed.allocate(pb, FMT(this->annotation_prefix, " ss1_rotl_packed"));

        // compute ss2
        ss2_bits.allocate(pb, 32, FMT(this->annotation_prefix, " ss2_bits"));
        compute_ss2.reset(new parity_gadget<FieldT>(pb, ss1_rotl_bits, a_rotl_bits, ONE, true, 0, 0, 0, ss2_bits, " compute_ss2"));
        ss2_packed.allocate(pb, FMT(this->annotation_prefix, " ss2_packed"));
        pack_ss2.reset(new packing_gadget<FieldT>(pb, ss2_bits, ss2_packed, FMT(this->annotation_prefix, " pack_ss2")));

        // compute ff
        ff.allocate(pb, FMT(this->annotation_prefix, " ff"));
        compute_ff.reset(new ff_gadget<FieldT>(pb, a, b, c, i, ff, " compute_ff"));

        // compute new_a(tt1)
        unreduced_new_a.allocate(pb, FMT(this->annotation_prefix, " unreduced_new_a"));
        packed_new_a.allocate(pb, FMT(this->annotation_prefix, " packed_new_a"));
        mod_reduce_new_a.reset(new lastbits_gadget<FieldT>(pb, unreduced_new_a, 32 + 2, packed_new_a, new_a, FMT(this->annotation_prefix, " mod_reduce_new_a")));

        // compute gg
        gg.allocate(pb, FMT(this->annotation_prefix, " gg"));
        compute_gg.reset(new gg_gadget<FieldT>(pb, e, f, g, i, gg, " compute_gg"));

        // compute tt2
        tt2_unreduced.allocate(pb, FMT(this->annotation_prefix, " tt2_unreduced"));
        tt2_packed.allocate(pb, FMT(this->annotation_prefix, " tt2_packed"));
        tt2_bits.allocate(pb, 32, FMT(this->annotation_prefix, " tt2_bits"));
        mod_reduce_tt2.reset(new lastbits_gadget<FieldT>(pb, tt2_unreduced, 32 + 2, tt2_packed, tt2_bits, FMT(this->annotation_prefix, " mod_reduce_tt2")));

        //compute new_e
        compute_new_e.reset(new permutation_gadget<FieldT>(pb, tt2_bits, new_e, 0, 9, 17, " compute_new_e"));
    }

    template <typename FieldT>
    void sm3_round_function_gadget<FieldT>::generate_r1cs_constraints()
    {
        pack_e->generate_r1cs_constraints(false);
        pack_d->generate_r1cs_constraints(false);
        pack_h->generate_r1cs_constraints(false);
        pack_a_rotl->generate_r1cs_constraints(false);

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                             a_rotl_packed + packed_e + T,
                                                             ss1_unreduced),
                                     FMT(this->annotation_prefix, " ss1_unreduced"));
        mod_reduce_ss1->generate_r1cs_constraints();

        compute_ss2->generate_r1cs_constraints();
        pack_ss2->generate_r1cs_constraints(false);

        compute_ff->generate_r1cs_constraints();

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                             ff + packed_d + ss2_packed + W_extended,
                                                             unreduced_new_a),
                                     FMT(this->annotation_prefix, " unreduced_new_a"));
        mod_reduce_new_a->generate_r1cs_constraints();

        compute_gg->generate_r1cs_constraints();

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                             gg + packed_h + ss1_packed + W,
                                                             tt2_unreduced),
                                     FMT(this->annotation_prefix, " tt2_unreduced"));
        mod_reduce_tt2->generate_r1cs_constraints();

        compute_new_e->generate_r1cs_constraints();
    }

    template <typename FieldT>
    void sm3_round_function_gadget<FieldT>::generate_r1cs_witness()
    {
        pack_e->generate_r1cs_witness_from_bits();
        pack_d->generate_r1cs_witness_from_bits();
        pack_h->generate_r1cs_witness_from_bits();

        compute_sigma0->generate_r1cs_witness();
        compute_sigma1->generate_r1cs_witness();

        compute_choice->generate_r1cs_witness();
        compute_majority->generate_r1cs_witness();

        pack_d->generate_r1cs_witness_from_bits();
        pack_h->generate_r1cs_witness_from_bits();

        this->pb.val(unreduced_new_a) = this->pb.val(packed_h) + this->pb.val(sigma1) + this->pb.val(choice) + FieldT(K) + this->pb.val(W) + this->pb.val(sigma0) + this->pb.val(majority);
        this->pb.val(unreduced_new_e) = this->pb.val(packed_d) + this->pb.val(packed_h) + this->pb.val(sigma1) + this->pb.val(choice) + FieldT(K) + this->pb.val(W);

        mod_reduce_new_a->generate_r1cs_witness();
        mod_reduce_new_e->generate_r1cs_witness();
    }
} // libsnark

#endif // SM3_COMPONENTS_TCC_